from sklearn.feature_extraction.text import CountVectorizer
from sklearn.feature_extraction.text import HashingVectorizer
from sklearn.linear_model import *
from sklearn.model_selection import train_test_split
import pandas as pd
import copy

from abc import abstractmethod
import time
import random
import pickle
import threading
import seal
import numpy as np
from seal import ChooserEvaluator, \
	Ciphertext, \
	Decryptor, \
	Encryptor, \
	EncryptionParameters, \
	Evaluator, \
	IntegerEncoder, \
	FractionalEncoder, \
	KeyGenerator, \
	MemoryPoolHandle, \
	Plaintext, \
	SEALContext, \
	EvaluationKeys, \
	GaloisKeys, \
	PolyCRTBuilder, \
	ChooserEncoder, \
	ChooserEvaluator, \
	ChooserPoly

import phe as paillier
from abc import ABC
pd.options.display.max_colwidth = 500

class Timer(object):

	def __init__(self):
		pass

	def __enter__(self):
		self.start = time.perf_counter()
		return self
	
	def __exit__(self, *args):
		end = time.perf_counter()
		self.delta = end - self.start

# Print parameters helper method from pySEAL
def print_parameters(context):
	print("/ Encryption parameters:")
	print("| poly_modulus: " + context.poly_modulus().to_string())

	# Print the size of the true (product) coefficient modulus
	print("| coeff_modulus_size: " + (str)(context.total_coeff_modulus().significant_bit_count()) + " bits")

	print("| plain_modulus: " + (str)(context.plain_modulus().value()))
	print("| noise_standard_deviation: " + (str)(context.noise_standard_deviation()))


class HomomorphicScheme(ABC):

	@abstractmethod
	def getEval(self):
		pass

	@abstractmethod
	def getCrypto(self):
		pass

class HomomorphicCryptography(ABC):
		
	@abstractmethod
	def decrypt(self, clf):
		pass

	def encrypt(self, clf):
		coefficents = clf.coef_[0]
		intercept = clf.intercept_[0]
		encrypted_coeffs, encrypted_intercept = self._encrypt(coefficents, intercept)
		return encrypted_coeffs, encrypted_intercept

	@abstractmethod
	def _encrypt(self, coefficents, intercept):
		pass

class HomomorphicEvaluator(ABC):

	@abstractmethod
	def evaluate(self, vector):
		pass

class SealScheme(HomomorphicScheme):

	def __init__(self, poly_modulus = 2048 ,bit_strength = 128 ,plain_modulus = 1<<8, integral_coeffs = 64, fractional_coeffs = 32, fractional_base = 3):
		parms = EncryptionParameters()
		parms.set_poly_modulus("1x^{} + 1".format(poly_modulus))

		if (bit_strength == 128):
			parms.set_coeff_modulus(seal.coeff_modulus_128(poly_modulus))
		else:
			parms.set_coeff_modulus(seal.coeff_modulus_192(poly_modulus))
		parms.set_plain_modulus(plain_modulus)

		self.parms = parms
		context = SEALContext(parms)

		keygen = KeyGenerator(context)
		public_key = keygen.public_key()
		secret_key = keygen.secret_key()

		self.encryptor = Encryptor(context, public_key)
		self.evaluator = Evaluator(context)
		self.decryptor = Decryptor(context, secret_key)
		self.encoder = FractionalEncoder(context.plain_modulus(), context.poly_modulus(), integral_coeffs, fractional_coeffs, fractional_base)

	def getCrypto(self):
		return SealCrypto(self.encoder, self.encryptor, self.decryptor, self.parms)

	def getEval(self):
		return SealEval(self.encoder, self.evaluator, self.parms)


class SealCrypto(HomomorphicCryptography):

	def __init__(self, encoder, encryptor, decryptor, parms):
		self.encoder = encoder
		self.encryptor = encryptor
		self.decryptor = decryptor
		self.parms = parms

	def _encrypt(self, coefficents, intercept):
		encrypted_coeffs = [Ciphertext(self.parms) for _ in range(len(coefficents))]
		for i in range(len(coefficents)):
			self.encryptor.encrypt(self.encoder.encode(coefficents[i]), encrypted_coeffs[i])
		encrypted_intercept = Ciphertext(self.parms)
		self.encryptor.encrypt(self.encoder.encode(intercept), encrypted_intercept)
		return encrypted_coeffs, encrypted_intercept

	def decrypt(self, encrypted_prediction):
		plaintext = Plaintext()
		self.decryptor.decrypt(encrypted_prediction,plaintext)
		return self.encoder.decode(plaintext)

	def get_noise_budget(self, ciphertext):
		return self.decryptor.invariant_noise_budget(ciphertext)

class SealEval(HomomorphicEvaluator):

	def __init__(self, encoder, evaluator, parms):
		self.encoder = encoder
		self.evaluator = evaluator
		self.parms = parms

	def set_encrypted_model(self, encrypted_model):
		self.encrypted_coeffs, self.encrypted_intercept = encrypted_model[0], encrypted_model[1]

	def evaluate(self, vector):
		encoded_vector = []
		for i in range(len(vector)):
			encoded_vector.append(self.encoder.encode(vector[i]))

		encrypted_array = [Ciphertext(self.parms) for _ in range(len(vector))]
		encrypted_result = Ciphertext(self.parms)

		for i in range(len(vector)):
			self.evaluator.multiply_plain(self.encrypted_coeffs[i], encoded_vector[i], encrypted_array[i])

		self.evaluator.add_many(encrypted_array, encrypted_result)

		self.evaluator.add(encrypted_result, self.encrypted_intercept)
		return encrypted_result

class PaillierScheme(HomomorphicScheme):

	def __init__(self, n_length=64, precision = 4):
		self.pubkey, self.private_key = paillier.generate_paillier_keypair(n_length=64)
		self.precision = precision

	def getCrypto(self):
		return PaillierCrypto(self.pubkey, self.private_key, self.precision)

	def getEval(self):
		return PaillierEval()

class PaillierCrypto(HomomorphicCryptography):

	def __init__(self,pubkey, private_key, precision):
		self.pubkey, self.private_key = pubkey, private_key
		self.precision = precision

	def _encrypt(self, coefficents, intercept):
		encrypted_coeffs = [self.pubkey.encrypt(c,precision=self.precision) for c in coefficents]
		encrypted_intercept = self.pubkey.encrypt(intercept,precision=self.precision)
		return encrypted_coeffs, encrypted_intercept

	def decrypt(self, encrypted_prediction):
		return self.private_key.decrypt(encrypted_prediction) 

	def get_noise_budget(self, ciphertext):
		return 0

class PaillierEval(HomomorphicEvaluator):

	def __init__(self):
		pass

	def set_encrypted_model(self, encrypted_model):
		self.encrypted_coeffs, self.encrypted_intercept = encrypted_model[0], encrypted_model[1]

	def evaluate(self, vector):
		encrypted_result = []
		for c,v in zip(self.encrypted_coeffs, vector):
			encrypted_result.append(c*v.item())
		encrypted_result = sum(encrypted_result) + self.encrypted_intercept
		return encrypted_result


class BenevolentBigBrother:

	def __init__(self , classifier, vectorizer, homomorphic_cryptography, testset = None, trainset = None):
		self.classifier = classifier
		self.vectorizer = vectorizer
		self.homomorphic_cryptography = homomorphic_cryptography
		self.testset = testset
		self.trainset = trainset

	def train(self):
		#print('Training {} with {}'.format(self.classifier.__class__.__name__, self.vectorizer.__class__.__name__))
		vectorize_text = self.vectorizer.fit_transform(self.trainset.tweets.values.astype('U'))
		self.classifier = self.classifier.fit(vectorize_text, self.trainset.pro_isis)
		vectorize_text = self.vectorizer.transform(self.testset.tweets.values.astype('U'))
		score = self.classifier.score(vectorize_text, self.testset.pro_isis)
		#print("Mean accuracy: {} ".format(score))
		return score

	def get_encrypted_model(self):
		self.encrypted_model = self.homomorphic_cryptography.encrypt(self.classifier)
		return self.encrypted_model

	def decrypt_result(self, encrypted_prediction):
		noise_budget = self.homomorphic_cryptography.get_noise_budget(encrypted_prediction)
		value = self.homomorphic_cryptography.decrypt(encrypted_prediction)
		return 1/(1+np.exp(-value)), noise_budget

	def plaintext_predict(self,tweet):
		return self.classifier.predict_proba(self.vectorizer.transform(tweet))[:,1][0]


class WinstonSmith:
	def __init__(self, data, homomorphic_eval, vectorizer, encrypted_model):
		homomorphic_eval.set_encrypted_model(encrypted_model)
		self.data = data
		self.homomorphic_eval = homomorphic_eval
		self.vectorizer = vectorizer

	def vectorize(self, text):
		return np.array(self.vectorizer.transform(text).todense())[0]


	def predict(self, vector):
		return self.homomorphic_eval.evaluate(vector)

	def talk(self):
		return self.data.sample(1)

def load_isis_dataset(pos_data, neg_data, test_size):
	print("Reading in datasets: {} as positive and {} as negative ".format(pos_data, neg_data))
	pro_isis = pd.read_csv(pos_data, encoding='latin-1')
	isis_neutral = pd.read_csv(neg_data, encoding='latin-1')
	isis_neutral["pro_isis"] = 0
	pro_isis["pro_isis"] = 1
	print("We want ~ 50/50 split on dataset, so will downsample neutral dataset from {} to 17392".format(isis_neutral.shape[0]))
	isis_neutral_sampled = isis_neutral.sample(n=17392)
	dataset = pd.concat([pro_isis,isis_neutral_sampled],ignore_index = True).sample(frac=1).reset_index(drop=True)
	print("Splitting train and test with {} / {} split ".format(int((1-test_size)*100), int(test_size*100)))
	trainset, testset = train_test_split(dataset, test_size=test_size)
	return trainset, testset

def example_situation(classifier, vectorizer, trainset, testset, tweet):

	seal_scheme = SealScheme()
	seal_crypto = seal_scheme.getCrypto()

	big_brother = BenevolentBigBrother(classifier, vectorizer, seal_crypto, trainset, testset)

	big_brother.train()

	encrypted_model = big_brother.get_encrypted_model()

	seal_eval = seal_scheme.getEval()
	winston = WinstonSmith(testset, seal_eval, vectorizer, encrypted_model)

	print("Winston's Tweet: {}".format(tweet.tweets.iloc[0].encode('utf-8')))

	tweet_vector = winston.vectorize(tweet.tweets)

	encrypted_prediction = winston.predict(tweet_vector)


	print("Model Encrypted Prediction: {}".format(encrypted_prediction))

	print("Sending encrypted prediction to BenevolentBigBrother...")

	decrypted_prediction, noise_budget = big_brother.decrypt_result(encrypted_prediction)

	print("Model Decrypted Prediction: {}".format(decrypted_prediction))
	print("Plaintext prediction: {}".format(big_brother.plaintext_predict(tweet.tweets.values.astype('U'))))
	print("Ground Truth: {}".format("Pro-ISIS" if (tweet.pro_isis.values == 1) else "Isis-Neutral"))
	print("Remaining Noise Budget: {} bits".format(str(noise_budget)))


def failure(entry, state, e):
	print("Failed at {} with {}".format(state, entry))
	print(e)

def perform_test(n_features, scheme, tweet, trainset, testset, entry):
	if (n_features == 11000): #Will use a CountVectorizer instead of HashVectorizer, higher accuracy but ~45k features
		vectorizer = CountVectorizer()
		entry["hash_or_count"] = "count"
	else:
		vectorizer = HashingVectorizer(n_features=n_features)
		entry["n_features"] = n_features
		entry["hash_or_count"] = "hash"

	classifier = LogisticRegression(n_jobs=-1)

	crypto = scheme.getCrypto()
	big_brother = BenevolentBigBrother(classifier, vectorizer, crypto, trainset = trainset, testset = testset)
	score = big_brother.train()
	entry["model_accuracy_score"] = score

	try:
		with Timer() as model_encryption_time:
			encrypted_model = big_brother.get_encrypted_model()
	except Exception as e:
		failure(entry, "model encryption", e)
		return entry

	entry["model_encryption_time"] = model_encryption_time.delta

	evaluation = scheme.getEval()
	winston = WinstonSmith(testset, evaluation, vectorizer, encrypted_model)

	tweet_vector = winston.vectorize(tweet.tweets)

	try:
		with Timer() as encrypted_evaluation_time:
			encrypted_prediction = winston.predict(tweet_vector)
	except Exception as e:
		failure(entry, "model evaluation", e)
		return entry
		
	entry["encrypted_evaluation_time"] = encrypted_evaluation_time.delta

	try:
		with Timer() as prediction_decryption_time:
			decrypted_prediction, noise_budget = big_brother.decrypt_result(encrypted_prediction)
	except Exception as e:
		failure(entry, "decryption prediction", e)
		return entry
		
	entry["prediction_decryption_time"] = prediction_decryption_time.delta
	entry["noise_budget"] = noise_budget
	ground_truth = big_brother.plaintext_predict(tweet.tweets.values.astype('U'))
	entry["decrypted_predictions_vs_ground_truth_diff"] = abs(ground_truth - decrypted_prediction)
	print(entry)
	return entry


def benchmark_FV_SEAL(trainset, testset, tweet, repeat = 5):
	np.random.seed(12345)
	random.seed(12345)
	seal_benchmark_dataframe = pd.DataFrame(columns = ["poly_modulus", "bit_strength", "plain_modulus","integral_coeffs", "fractional_coeffs", "n_features", "count_or_hash", "scheme_initialization_time", "model_accuracy_score", "model_encryption_time","encrypted_evaluation_time","prediction_decryption_time", "noise_budget", "decrypted_predictions_vs_ground_truth_diff"])

	poly_moduli = [1024]
	#1024, 2048, 4096, 1024, 2048, 4096, 8192, 16384, 
	bit_strengths = [128]
	plain_moduli = [1 << 4]
	integral_coeffs_set = [32]
	fractional_coeffs_set = [64]
	n_features_set = [n for n in range(1000,11000,1000)]
	#bit_strengths = [128,192]
	# plain_moduli = [1<<n for n in range(4,20)]
	# integral_coeffs_set = [1<<n for n in range(3,8)]
	# fractional_coeffs_set = [1<<n for n in range(3,8)]
	# n_features_set = [n for n in range(1000,12000,1000)]


	for poly_modulus in poly_moduli:
		for bit_strength in bit_strengths:
			for plain_modulus in plain_moduli:
				for integral_coeffs in integral_coeffs_set:
					for fractional_coeffs in fractional_coeffs_set:
						for n_features in n_features_set:
							for _ in range(repeat):
								entry = {"poly_modulus": poly_modulus, 
								"bit_strength": bit_strength, 
								"plain_modulus": plain_modulus,
								"integral_coeffs": integral_coeffs,
								"fractional_coeffs": fractional_coeffs}

								try:
									with Timer() as scheme_initialization_time:
										seal_scheme = SealScheme(poly_modulus = poly_modulus, bit_strength = bit_strength, plain_modulus = plain_modulus, integral_coeffs = integral_coeffs, fractional_coeffs = fractional_coeffs)
								except Exception as e:
									df = failure(df, entry, "scheme initialization", e)
									continue

								entry["scheme_initialization_time"] = scheme_initialization_time.delta

								seal_benchmark_dataframe = seal_benchmark_dataframe.append(perform_test(n_features, seal_scheme, tweet, trainset, testset, entry), ignore_index = True)

	print("Saving benchmark file...")
	seal_benchmark_dataframe.to_csv("FV_benchmark6.csv")

def benchmark_paillier(trainset, testset, tweet, repeat = 10):
	np.random.seed(12345)
	random.seed(12345)
	paillier_benchmark_dataframe = pd.DataFrame(columns = ["n_length", "precision", "n_features", "count_or_hash", "scheme_initialization_time", "model_accuracy_score", "model_encryption_time","encrypted_evaluation_time","prediction_decryption_time","decrypted_predictions_vs_ground_truth_diff"])
	n_lengths = [1<<n for n in range(5,10)]
	precisions = [4]
	n_features_set = [1000]
	#n_features_set = [n for n in range(1000,12000,1000)]
	for n_length in n_lengths:
		for precision in precisions:
			for n_features in n_features_set:
				for _ in range(repeat):
					entry = {"n_length": n_length,
					"precision": precision}

					try:
						with Timer() as scheme_initialization_time:
							paillier_scheme = PaillierScheme(n_length = n_length, precision = precision)
					except Exception as e:
						print("Failed at scheme initialization with {}".format(entry))
						print(e)
						paillier_benchmark_dataframe.append(entry, ignore_index=True)
						continue
					entry["scheme_initialization_time"] = scheme_initialization_time.delta
					
					paillier_benchmark_dataframe = paillier_benchmark_dataframe.append(perform_test(n_features, paillier_scheme, tweet, trainset, testset, entry), ignore_index = True)

	print("Saving benchmark file...")
	paillier_benchmark_dataframe.to_csv("paillier_benchmark1.csv")


np.random.seed(3352)
random.seed(3336)
trainset, testset = load_isis_dataset("IsisFanboy.csv", "AboutIsis.csv", 0.1)
tweet = testset.sample(1)
print("Using tweet: {}".format(tweet))
print(tweet.tweets.values[0].encode('utf-8'))
classifier = LogisticRegression(n_jobs=-1)
vectorizer = CountVectorizer()
example_situation(classifier, vectorizer, trainset, testset, tweet)

#benchmark_paillier(trainset, testset, tweet)
#benchmark_FV_SEAL(trainset, testset, tweet)





















	



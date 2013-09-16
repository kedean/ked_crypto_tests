import math

class AES_Component(object):
	SUB_TABLE = [
		[0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76],
		[0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0],
		[0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15],
		[0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75],
		[0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84],
		[0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF],
		[0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8],
		[0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2],
		[0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73],
		[0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB],
		[0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79],
		[0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08],
		[0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A],
		[0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E],
		[0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF],
		[0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16]
	]

	INV_SUB_TABLE = [
		[0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB],
		[0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB],
		[0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E],
		[0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25],
		[0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92],
		[0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84],
		[0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06],
		[0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B],
		[0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73],
		[0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E],
		[0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B],
		[0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4],
		[0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F],
		[0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF],
		[0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61],
		[0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D]
	]

	@staticmethod
	def subByte(original, inverse=False):
		left_hex = original / 16 #left digit of the hexadecimal representation of the byte
		right_hex = original % 16 #corresponding right half
		if not inverse:
			return AES_Component.SUB_TABLE[left_hex][right_hex] #fetch from the subtable using the two digits as lookup values
		else:
			return AES_Component.INV_SUB_TABLE[left_hex][right_hex] #the inverse subByte fetches from a separate table

class AES_KeySchedule(AES_Component):

	RCON = [
		[0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36],
		[0x00] * 10,
		[0x00] * 10,
		[0x00] * 10
	]

	def __init__(self, key):
		self.__base_key = list(key)
		self.__schedule = list(key)
		for row in range(0, 4):
			self.__schedule[row].extend([0] * 4 * 11)

	def generate(self):
		yield [row[0:4] for row in self.__schedule]

		for i in range(1, 11):
			start_column = i * 4
			self.__schedule = AES_KeySchedule.setColumn(self.__schedule, start_column, AES_KeySchedule.getColumn(self.__schedule, start_column - 1))

			self.rotWord(start_column)
			self.subBytes(start_column)
			self.addRcon(start_column, i - 1)

			for j in range(1, 4):
				self.makeRestColumn(start_column + j)

			yield [row[i*4:i*4 + 4] for row in self.__schedule]


	@property
	def base_key(self):
		return self.__base_key

	@staticmethod
	def getColumn(source, column):
		return [source[row][column] for row in range(0, 4)]
	@staticmethod
	def setColumn(source, column, new_values):
		for row in range(0, len(source)):
			try:
				source[row][column] = new_values[row]
			except:
				source[row].append(new_values[row])
		return source
	def rotWord(self, column):
		column_values = AES_KeySchedule.getColumn(self.__schedule, column)
		for row in range(0, 4):
			self.__schedule[row][column] = column_values[(row + 1) % 4]
	def subBytes(self, column):
		column_values = AES_KeySchedule.getColumn(self.__schedule, column)
		for row in range(0, 4):
			new_byte = AES_Block.subByte(column_values[row])
			self.__schedule[row][column] = new_byte
	def addRcon(self, column, rcol):
		column_values = AES_KeySchedule.getColumn(self.__schedule, column)
		four_ago = AES_KeySchedule.getColumn(self.__schedule, column - 4)
		xor_cols = [four_ago[row] ^ column_values[row] for row in range(0, 4)]
		rcon = AES_KeySchedule.getColumn(self.RCON, rcol)
		xor_rcon = [xor_cols[row] ^ rcon[row] for row in range(0, 4)]
		self.__schedule = AES_KeySchedule.setColumn(self.__schedule, column, xor_rcon)
	def makeRestColumn(self, column):
		last_column = AES_KeySchedule.getColumn(self.__schedule, column - 1)
		four_ago_column = AES_KeySchedule.getColumn(self.__schedule, column - 4)
		xor_cols = [four_ago_column[row] ^ last_column[row] for row in range(0, 4)]
		self.__schedule = AES_KeySchedule.setColumn(self.__schedule, column, xor_cols)

	def getRoundKey(self, round_index):
		return [row[round_index*4:round_index*4 + 4] for row in self.__schedule]

class AES_Block(AES_Component):

	def __init__(self, state, key):
		assert len(state) == len(key)

		self.__state = state
		self.__key_schedule = AES_KeySchedule(key).generate()

	def addRoundKey(self):
		round_key = self.__key_schedule.next()
		
		for row in range(0, 4):
			for column in range(0, 4):
				self.__state[row][column] ^= round_key[row][column]

	def subBytes(self, inverse=False):
		for x in range(0, 4):
			for y in range(0, 4):
				new_byte = AES_Block.subByte(self.__state[x][y], inverse=inverse)
				self.__state[x][y] = new_byte
	def shiftRows(self, inverse=False):
		for row in range(0, 4):
			new_row = [self.__state[row][((i + row) if not inverse else (i - row)) % 4] for i in range(0, 4)]
			self.__state[row] = new_row

	@staticmethod
	def finiteFieldMultiply(left, right):
		p = 0
		hi_bit_set = 0
		for counter in range(0, 8):
			if (right & 1) != 0:
				p ^= left
			hi_bit_set = left & 0x80
			left <<= 1
			if hi_bit_set != 0:
				left ^= 0x1b
			right >>= 1
		return p
	def mixColumns(self, inverse=False):
		mixer = [
			[2, 3, 1, 1],
			[1, 2, 3, 1],
			[1, 1, 2, 3],
			[3, 1, 1, 2]
		] if not inverse else [
			[14, 11, 13, 9],
			[9, 14, 11, 13],
			[13, 9, 14, 11],
			[11, 13, 9, 14]
		]

		for column in range(0, 4):
			new_column = [((AES_Block.finiteFieldMultiply(self.__state[0][column], mixer[row][0]) ^ AES_Block.finiteFieldMultiply(self.__state[1][column], mixer[row][1]) ^ AES_Block.finiteFieldMultiply(self.__state[2][column], mixer[row][2]) ^ AES_Block.finiteFieldMultiply(self.__state[3][column], mixer[row][3])) % 256) for row in range(0, 4)]
			for row in range(0, 4):
				self.__state[row][column] = new_column[row]

	def encryptBlock(self):
		self.addRoundKey()
		
		for i in range(0, 10):
			self.subBytes()
			self.shiftRows()
			if i != 9:
				self.mixColumns()
			self.addRoundKey()

	def decryptBlock(self):
		for i in range(0, 10):
			self.addRoundKey()
			if i != 0:
				self.mixColumns(inverse=True)
			self.shiftRows(inverse=True)
			self.subBytes(inverse=True)
		self.addRoundKey()

	
	@property
	def state(self):
		return self.__state

class AES_Cipher(object):
	ECB_MODE, CBC_MODE, CFB_MODE, CTR_MODE = 0, 1, 2, 3

	def __init__(self, key, key_size, mode):
		if key_size != 128:
			raise NotImplementedError("Only 128-bit ciphers are supported at this time.")
		self.__num_key_vals = key_size / 8 #number of bytes in the key
		self.__key_dim = int(math.sqrt(self.__num_key_vals)) #the square dimension of the key and state matrices
		self.__key_size = key_size
		if len(key) == self.__num_key_vals:
			for x in key:
				assert type(x) == int
			self.__key = self.listToColumnMajor(key)
		else:
			assert len(key) == self.__key_dim
			for row in key:
				assert len(row) == self.__key_dim
			self.__key = key
		
		self.__mode = mode
	def toBlocks(self, data):
		if len(data) % 16 != 0: #block sizes in AES are fixed at 128, or 8*16bytes
			data = list(data) + [0] * (16 - (len(data) % 16))
		else:
			data = list(data)
		data = [ord(x) if type(x) == str else int(x) for x in data]
		num_blocks = int(len(data) / 16)
		for i in range(0, num_blocks):
			yield self.listToColumnMajor(data[i*16:i*16 + 16])

	def encrypt(self, data, iv=None):
		if self.__mode == self.ECB_MODE or self.__mode == "ecb":
			return self.ecb_encrypt(data)
		elif self.__mode == self.CBC_MODE or self.__mode == "cbc":
			raise NotImplementedError("Only ECB mode is supported at this time.")
		elif self.__mode == self.CFB_MODE or self.__mode == "cfb":
			raise NotImplementedError("Only ECB mode is supported at this time.")
		elif self.__mode == self.CTR_MODE or self.__mode == "ctr":
			raise NotImplementedError("Only ECB mode is supported at this time.")
		else:
			raise ValueError("Please specify ECB, CBC, CFB, or CTR mode.")
	def decrypt(self, data, iv=None):
		raise NotImplementedError("Decryption does not function at this time.")
		if self.__mode == self.ECB_MODE or self.__mode == "ecb":
			return self.ecb_decrypt(data)
		elif self.__mode == self.CBC_MODE or self.__mode == "cbc":
			raise NotImplementedError("Only ECB mode is supported at this time.")
		elif self.__mode == self.CFB_MODE or self.__mode == "cfb":
			raise NotImplementedError("Only ECB mode is supported at this time.")
		elif self.__mode == self.CTR_MODE or self.__mode == "ctr":
			raise NotImplementedError("Only ECB mode is supported at this time.")
		else:
			raise ValueError("Please specify ECB, CBC, CFB, or CTR mode.")
	
	def ecb_encrypt(self, data):
		blocks = self.toBlocks(data)

		output = []
		for sub_data in blocks:
			cipher = AES_Block(sub_data, self.__key)
			cipher.encryptBlock()
			output.extend(cipher.state)
		return output
	def ecb_decrypt(self, data):
		blocks = self.toBlocks(data)

		output = []
		for sub_data in blocks:
			cipher = AES_Block(sub_data, self.__key)
			cipher.decryptBlock()
			output.extend(cipher.state)
		return output

	def listToColumnMajor(self, L):
		output = []
		
		assert len(L) == self.__num_key_vals

		for offset in range(0, self.__key_dim):
			row = []
			for item in range(offset, len(L), self.__key_dim):
				row.append(L[item])
			output.append(row)

		return output
	@staticmethod
	def hex_state(data):
		if type(data[0]) == list:
			return [[hex(j) for j in i] for i in data]
		else:
			return [hex(item) for item in data]
	@staticmethod
	def matrix_to_list(data):
		output = []
		for column in range(0, 4):
			for row in range(0, 4):
				output.append((data[row][column]))
		return output


key = [0xf0, 0xca, 0x60, 0xab, 0xd4, 0x4f, 0x20, 0x1c, 0x89, 0x56, 0xb3, 0xad, 0x0e, 0xeb, 0x1a, 0x7a]

base_state = [
	0x00, 0x11, 0x22, 0x33,
	0x44, 0x55, 0x66, 0x77,
	0x00, 0x11, 0x22, 0x33,
	0x44, 0x55, 0x66, 0x77
]

cipher = AES_Cipher(range(0, 8) * 2, 128, "ecb")
data = cipher.encrypt(base_state)

import pprint
pprint.pprint(cipher.hex_state(data))
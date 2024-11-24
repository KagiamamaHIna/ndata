#include "nEAdata.h"
#define CBC 0
#define ECB 0

namespace ndata {//要有自己的C++签名（
#include "aes.h"
#include "aes.c"
}

namespace ndata {

	uint32_t GetU8VecDW(const std::vector<uint8_t>& srcData, size_t index);
	std::vector<uint8_t> DeepCopyU8(const std::vector<uint8_t>& srcData, size_t index, size_t size);
	void WriteBinFile(const std::string& path, const std::vector<uint8_t>& BinData);

	typedef uint8_t AvxKey[16];
	typedef uint8_t AvxIv[16];

	static void DecryptBlock(uint8_t* blockDatas, size_t size, AvxKey key, AvxIv iv) {
		//初始化AES_ctx对象
		AES_ctx ctx;
		AES_init_ctx_iv(&ctx, key, iv);
		AES_CTR_xcrypt_buffer(&ctx, blockDatas, size);
	}

	void EADataWak::GetIVForNum(uint32_t index, uint8_t iv[16]) const {
		class NollaRNG {
		public:
			NollaRNG(uint32_t setSeed, bool isBeta) {
				seed = setSeed;
				if (isBeta && seed > 2147483647.0) {
					seed *= 0.5;
				}
			}
			double Next() {
				double v4 = (int32_t)seed * 0x41a7 + ((int32_t)seed / 0x1f31d) * -0x7fffffff;
				if (v4 < 0)
				{
					v4 += 0x7fffffff;
				}
				seed = v4;
				return (double)v4 * 4.656612875e-10;
			}
		private:
			double seed;
		};

		NollaRNG rng = NollaRNG(index + 23456911, beta);
		for (size_t i = 0; i < 16; i++) {
			iv[i] = 0;
		}
		rng.Next();
		for (size_t i = 0; i < 4; i++) {
			uint32_t u32 = (uint32_t)(rng.Next() * -2147483648.0);
			size_t WriteIndex = i * 4;
			iv[WriteIndex] |= u32;
			iv[WriteIndex + 1] |= u32 >> 8;
			iv[WriteIndex + 2] |= u32 >> 16;
			iv[WriteIndex + 3] |= u32 >> 24;
		}
	}

	std::vector<uint8_t> EADataWak::DecryptData(const std::vector<uint8_t>& EAdata) {
		if (EAdata.size() < 16) {
			throw DataFileTypeErrorException(0);
		}
		AvxKey key;
		AvxIv iv;
		AvxIv FileIv;
		GetIVForNum(0, key);
		GetIVForNum(1, iv);
		GetIVForNum(0x7FFFFFFE, FileIv);
		std::vector<uint8_t> result = EAdata;
		size_t dataSize = result.size();

		DecryptBlock(result.data(), 16, key, iv);//解密开头元数据块

		uint32_t PathSize = GetU8VecDW(result, 8);
		if (PathSize > dataSize) throw DataPathSizeOutOfBoundsException(16);

		DecryptBlock(result.data() + 16, PathSize - 16, key, FileIv);//解密路径块
		int32_t FileCount = 0;
		for (size_t i = 16; i + 12 < PathSize; i += 12) {//第一个四字节是位置关系，第二个四字节是大小关系，第三个四字节是文件目录字符串的长度
			uint32_t FilePos = GetU8VecDW(result, i);
			uint32_t FileSize = GetU8VecDW(result, i + 4);
			uint32_t FilePathSize = GetU8VecDW(result, i + 8);
			if (FilePos > dataSize) {
				throw DataFileOutOfBoundsException(FilePos);
			}
			GetIVForNum(FileCount, iv);
			DecryptBlock(result.data() + FilePos, FileSize, key, iv);
			i += FilePathSize;
			FileCount++;
		}

		return result;
	}

	std::vector<uint8_t> EADataWak::DumpEncryptWak() const {
		std::vector<uint8_t> decryptData = DumpWak();
		size_t dataSize = decryptData.size();
		uint32_t PathSize = GetU8VecDW(decryptData, 8);
		AvxKey key;
		AvxIv iv;
		AvxIv FileIv;
		GetIVForNum(0, key);
		GetIVForNum(1, iv);
		GetIVForNum(0x7FFFFFFE, FileIv);
		DecryptBlock(decryptData.data(), 16, key, iv);//加密元数据块
		int32_t FileCount = 0;
		for (size_t i = 16; i + 12 < PathSize; i += 12) {//第一个四字节是位置关系，第二个四字节是大小关系，第三个四字节是文件目录字符串的长度
			uint32_t FilePos = GetU8VecDW(decryptData, i);
			uint32_t FileSize = GetU8VecDW(decryptData, i + 4);
			uint32_t FilePathSize = GetU8VecDW(decryptData, i + 8);

			GetIVForNum(FileCount, iv);
			DecryptBlock(decryptData.data() + FilePos, FileSize, key, iv);
			i += FilePathSize;
			FileCount++;
		}
		DecryptBlock(decryptData.data() + 16, PathSize - 16, key, FileIv);//加密路径块
		return decryptData;
	}

	void EADataWak::DumpEncryptWakToFile(const std::string& path) const {
		WriteBinFile(path, DumpEncryptWak());
	}

	EADataWak ea_wizard_get_pak(const std::string& path) {//由于是明文存储，所以直接调用wizard_get_pak然后深拷贝umap即可
		EADataWak eadata;
		eadata.umap() = wizard_get_pak(path).umap();
		return eadata;
	}

	void ea_wizard_pak(const std::string& WakPath, const std::string& path) {
		ea_wizard_get_pak(path).DumpEncryptWakToFile(WakPath);
	}

	void ea_wizard_unpak(const std::string& WakPath, const std::string& path) {
		EADataWak(WakPath).DumpFiles(path);
	}
}

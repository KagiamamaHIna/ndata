#pragma once
#include "ndata.h"

namespace ndata {
	class EADataWak;
	EADataWak ea_wizard_get_pak(const std::string& path);//类似于wizard_get_pak
	void ea_wizard_pak(const std::string& WakPath, const std::string& path);//指定一个路径，将路径下的文件全部打包成wak，带有data前缀
	void ea_wizard_unpak(const std::string& WakPath, const std::string& path);//指定一个wak路径，将wak解包至指定路径下

	class EADataWak : public DataWak {
	public:
		EADataWak(bool isBeta = false) : beta(isBeta), DataWak() {}
		EADataWak(const std::vector<uint8_t>& data, bool isBeta = false) :beta(isBeta), DataWak(DecryptData(data)) {}
		EADataWak(const std::string& WakPath, bool isBeta = false) : EADataWak(ReadBinFile(WakPath), isBeta) {}
		EADataWak(const char* WakPath, bool isBeta = false) : EADataWak(std::string(WakPath), isBeta) {}//从路径构造
		virtual ~EADataWak() = default;

		std::vector<uint8_t> DumpEncryptWak() const;//导出成加密形式的data.wak二进制数据
		void DumpEncryptWakToFile(const std::string& path) const;//导出成加密形式的data.wak文件

		void SetIsBeta(bool isBeta) {//后续可以手动再设置
			beta = isBeta;
		}

		bool GetIsBeta() const {
			return beta;
		}
	private:
		std::vector<uint8_t> DecryptData(const std::vector<uint8_t>& data);//解密函数，由这个解密完成后丢给DataWak的构造函数完成类构造
		void GetIVForNum(uint32_t index, uint8_t iv[16]) const;
		bool beta;
	};
}

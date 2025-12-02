#include <fstream>

namespace mem_bin_help
{
	struct BinaryHelperBase
	{
		virtual void read_to_memory(size_t offset, void* dst, size_t size) = 0;
		virtual ~BinaryHelperBase() {};

		template<typename OBJECT>
		OBJECT read_object(size_t offset)
		{
			OBJECT object{};
			read_to_memory(offset, &object, sizeof(OBJECT));
			return object;
		}
	};

	struct BinaryHelperFile : public BinaryHelperBase
	{
		BinaryHelperFile(const std::string& file)
			: m_stream(file, std::ios::binary | std::ios::in) {
		}

		virtual void read_to_memory(size_t offset, void* dst, size_t size) override
		{
			m_stream.seekg(offset, std::ios::beg);
			m_stream.read(reinterpret_cast<char*>(dst), size);
		}

	private:
		std::ifstream m_stream;
	};

	struct BinaryHelperBuffer : public BinaryHelperBase
	{
		BinaryHelperBuffer(uint8_t* buffer)
			: m_buffer(buffer) {
		}

		virtual void read_to_memory(size_t offset, void* dst, size_t size) override
		{
			memcpy(dst, m_buffer + offset, size);
		}

	private:
		uint8_t* m_buffer;
	};
}
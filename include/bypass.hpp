#include <Windows.h>
#include <vector>
#include <TlHelp32.h>

class Bypass{

    private:
        HANDLE m_hProcess = 0;
        HANDLE m_hSnap = 0;

    public:
        Bypass();
        ~Bypass();

        DWORD getPID(const wchar_t* PROCESS_NAME){ //contrived way to get the processID of a windows process similar to the msft reference code
            DWORD PID = 0;
            m_hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

            if(m_hSnap != INVALID_HANDLE_VALUE){

                PROCESSENTRY32 procEntry;
                procEntry.dwSize = sizeof(procEntry);

                if(Process32First(m_hSnap, &procEntry)) //grab the first process
                    do{
                        if(!_wcsicmp(procEntry.szExeFile, PROCESS_NAME)){ //wide char compare, thats why we're using wide char and not c++ strings
                            PID = procEntry.th32ProcessID;
                            break;
                        }
                    } while(Process32Next(m_hSnap, &procEntry)); //loop through the processes looking for a match
            }

            CloseHandle(m_hSnap); //destroy current snap handle
            return PID;
        }

        uintptr_t GetModuleBaseAddress(DWORD pid, const wchar_t* moduleName){

            uintptr_t ModuleBaseAddress = 0;
            m_hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);

            if(m_hSnap != INVALID_HANDLE_VALUE){

                MODULEENTRY32 modEntry;
                modEntry.dwSize = sizeof(modEntry);
                if(Module32First(m_hSnap, &modEntry)){

                    do{
                            if(!_wcsicmp(modEntry.szModule, moduleName)){
                                ModuleBaseAddress = (uintptr_t)modEntry.modBaseAddr;
                            }
                    }while(Module32Next(m_hSnap, &modEntry));
                }

            }
            CloseHandle(m_hSnap);
            return ModuleBaseAddress;
        }

        bool Attach(DWORD pid){

            m_hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, pid);
            if(m_hProcess != 0) return true;
            else return false;
        };

        bool Read(uintptr_t lpBaseAddress, void* lpBuffer, SIZE_T nSize, SIZE_T* LpNumberOfBytesRead = 0){ //pass in the buffer address

            BOOL rtn_read = ReadProcessMemory(m_hProcess, (LPCVOID)lpBaseAddress, lpBuffer, nSize, LpNumberOfBytesRead);
            if(rtn_read) return true;
            else return false;
        };

        bool ReadStdString(uintptr_t lpBaseAddress, void* lpBuffer, SIZE_T* LpNumberOfBytesRead = 0){

            int array_size;
            BOOL rtn_arr_size = ReadProcessMemory(m_hProcess, (LPCVOID)(lpBaseAddress + 0x8), &array_size, sizeof(int), LpNumberOfBytesRead);
            array_size++;
            if(!rtn_arr_size)
                return false;
            if(array_size > 15){

                uintptr_t addrOfCharArray;
                //dereference the pointer in the second member variable to get the dynamic address of the array
                ReadProcessMemory(m_hProcess, (BYTE*)(lpBaseAddress + sizeof(void*)), &addrOfCharArray, sizeof(void*), 0);

                char buffer[500];
                //Read the array into buffer, +1 to get the 0 terminator
                ReadProcessMemory(m_hProcess, (BYTE*)(addrOfCharArray), &buffer, array_size + 1, 0);

                //copy the buffer into our ouput argument
                memcpy(lpBuffer, &buffer, strlen(buffer) + 1);

            }

            else Bypass::Read(lpBaseAddress, lpBuffer, array_size);

            return true;   

        };

        bool Write(uintptr_t lpBaseAddress, void* lpBuffer, SIZE_T nSize, SIZE_T* LpNumberOfBytesWritten = 0){ //pass in the buffer address

            BOOL rtn_write = WriteProcessMemory(m_hProcess, (LPVOID)lpBaseAddress, lpBuffer, nSize, LpNumberOfBytesWritten);
            if(rtn_write) return true;
            else return false;
        };

        uintptr_t FindDMA_addr(uintptr_t ptr, std::vector<u_int> offsets){ //processID, base address of target proces

            uintptr_t addr = ptr;
            for(unsigned int i = 0; i < offsets.size(); i++) {
                Bypass::Read(addr, &addr, sizeof(addr));
                addr += offsets[i]; //this is kind of weird, but its gonna automatically dereference and add the pointers over and over
            }
            return addr;
            
        }


};

Bypass::Bypass() {}

Bypass::~Bypass(){

    if(m_hProcess != 0) CloseHandle(m_hProcess); //respect RAII bless up
}
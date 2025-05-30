#include "CPacker.h"
#define NUM_SECTION 4

#define CODE_DECRYPT 0x1000

CPacker::CPacker()
{
}

CPacker::~CPacker()
{
    UnmapViewOfFile(m_pPeBuff);
    delete[] m_pEnCode;
    delete[] m_pNewPeHdr;
    delete[] m_pNewSecTable;
    delete[] m_pNewPe;
    m_pPeBuff = nullptr;
    m_pEnCode = nullptr;
    m_pNewPeHdr = nullptr;
    m_pNewSecTable = nullptr;
    m_pNewPe = nullptr;
}

BOOL CPacker::AddShell(CString strPath)
{
    //����PE
    if (!AnalyzePe(strPath))
    {
        return FALSE;
    }
    //���ܴ����
    EncryptCode();
    //������PE
    //����ڱ�
    m_nNewSecTable = sizeof(IMAGE_SECTION_HEADER) * (NUM_SECTION+1);
    m_pNewSecTable = new IMAGE_SECTION_HEADER[NUM_SECTION + 1];
    ZeroMemory(m_pNewSecTable, m_nNewSecTable);
            //1.�ս�
    strcpy((char*)m_pNewSecTable[0].Name, ".zyx");
    m_pNewSecTable[0].Misc.VirtualSize = m_pNtHdr->OptionalHeader.SizeOfImage;
    m_pNewSecTable[0].VirtualAddress = m_pSecHdrs[0].VirtualAddress;
    m_pNewSecTable[0].SizeOfRawData = 0;   //�ս�û���ļ���С
    m_pNewSecTable[0].PointerToRawData = 0;
    m_pNewSecTable[0].Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;  //�ɶ���д��ִ��
            //2.���ܹ����Դ�����
    strcpy((char*)m_pNewSecTable[1].Name, ".data");
    m_pNewSecTable[1].Misc.VirtualSize = m_pNtHdr->OptionalHeader.SizeOfImage;
    m_pNewSecTable[1].VirtualAddress = m_pNewSecTable[0].VirtualAddress+ m_pNewSecTable[0].Misc.VirtualSize;
    m_pNewSecTable[1].SizeOfRawData = GetAlign(m_nFileSize, m_pNtHdr->OptionalHeader.FileAlignment);
    m_pNewSecTable[1].PointerToRawData = m_pNtHdr->OptionalHeader.SizeOfHeaders;
    m_pNewSecTable[1].Characteristics =  IMAGE_SCN_MEM_READ ; 
            //3.���ܼ��ؽ�
    strcpy((char*)m_pNewSecTable[2].Name, ".code");
    m_pNewSecTable[2].Misc.VirtualSize = GetAlign(CODE_DECRYPT, m_pNtHdr->OptionalHeader.SectionAlignment);
    m_pNewSecTable[2].VirtualAddress = m_pNewSecTable[1].VirtualAddress+ m_pNewSecTable[1].Misc.VirtualSize;
    m_pNewSecTable[2].SizeOfRawData = GetAlign(CODE_DECRYPT, m_pNtHdr->OptionalHeader.FileAlignment);
    m_pNewSecTable[2].PointerToRawData = m_pNewSecTable[1].PointerToRawData+ m_pNewSecTable[1].SizeOfRawData;
    m_pNewSecTable[2].Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ ;  //�ɶ���ִ��
            //4.��Դ��
    IMAGE_DATA_DIRECTORY res = m_pNtHdr->OptionalHeader.DataDirectory[2];
    strcpy((char*)m_pNewSecTable[3].Name, ".rsrc");
    m_pNewSecTable[3].Misc.VirtualSize = GetAlign(res.Size, m_pNtHdr->OptionalHeader.SectionAlignment);
    m_pNewSecTable[3].VirtualAddress = m_pNewSecTable[2].VirtualAddress + m_pNewSecTable[2].Misc.VirtualSize;
    m_pNewSecTable[3].SizeOfRawData = GetAlign(res.Size, m_pNtHdr->OptionalHeader.FileAlignment);
    m_pNewSecTable[3].PointerToRawData = m_pNewSecTable[2].PointerToRawData + m_pNewSecTable[2].SizeOfRawData;
    m_pNewSecTable[3].Characteristics = 0x40000040;  //�ɶ�
        //����PEͷ
    m_nNewHdrPeSize = m_pNtHdr->OptionalHeader.SizeOfHeaders;
    m_pNewPeHdr = new BYTE[m_nNewHdrPeSize];
    memcpy(m_pNewPeHdr, m_pPeBuff, m_nNewHdrPeSize);
    PIMAGE_DOS_HEADER pDosHdr = (PIMAGE_DOS_HEADER)m_pNewPeHdr;
    PIMAGE_NT_HEADERS pNtHdr = (PIMAGE_NT_HEADERS)(m_pNewPeHdr + m_pDosHdr->e_lfanew);
    PIMAGE_SECTION_HEADER pSecHdrs = (PIMAGE_SECTION_HEADER)((uint8_t*)&pNtHdr->OptionalHeader + pNtHdr->FileHeader.SizeOfOptionalHeader);
            //�޸Ľڱ���Ŀ
    pNtHdr->FileHeader.NumberOfSections = NUM_SECTION;
            //�޸���ڵ�
    pNtHdr->OptionalHeader.AddressOfEntryPoint = m_pNewSecTable[2].VirtualAddress;
            //�޸����ڴ���ܴ�С  
    pNtHdr->OptionalHeader.SizeOfImage = m_pNewSecTable[NUM_SECTION-1].VirtualAddress + m_pNewSecTable[NUM_SECTION - 1].Misc.VirtualSize; //���һ���ڵĵ�ַ + ��С
            //�޸�����Ŀ¼
    ZeroMemory(pNtHdr->OptionalHeader.DataDirectory, sizeof(pNtHdr->OptionalHeader.DataDirectory));
    pNtHdr->OptionalHeader.DataDirectory[2].VirtualAddress = m_pNewSecTable[3].VirtualAddress;
    pNtHdr->OptionalHeader.DataDirectory[2].Size = res.Size;
            //�����ڱ�
    CopyMemory(pSecHdrs, m_pNewSecTable, m_nNewSecTable);   

    //�����µ�PE�ļ�
    m_nNewPe = m_pNewSecTable[NUM_SECTION - 1].PointerToRawData + m_pNewSecTable[NUM_SECTION - 1].SizeOfRawData;
    m_pNewPe = new BYTE[m_nNewPe];
    ZeroMemory(m_pNewPe, m_nNewPe);
        //���PEͷ
    CopyMemory(m_pNewPe, m_pNewPeHdr, m_nNewHdrPeSize);
        //�����ܹ��Ĵ����
    CopyMemory(m_pNewPe+m_pNewSecTable[1].PointerToRawData, m_pEnCode, m_nEnCodeSize);
        //�����ܲ���
    CopyMemory(m_pNewPe + m_pNewSecTable[2].PointerToRawData, m_pCode, m_nCode);
        //�����Դ��
    DWORD FOA_res = RVA2FOA(res.VirtualAddress);
    if (FOA_res != 0)
    {
        CopyMemory(m_pNewPe + m_pNewSecTable[3].PointerToRawData, m_pPeBuff + FOA_res, res.Size);
        //�޸���Դ��
        RepairResource((PIMAGE_RESOURCE_DIRECTORY)(m_pNewPe + m_pNewSecTable[3].PointerToRawData));
    }
    CString strDstPath = strPath.Left(strPath.ReverseFind('.')) + "_pack"+ "."+"exe";
    HANDLE hFile = CreateFile(strDstPath,           
        GENERIC_WRITE,             
        FILE_SHARE_READ,           
        NULL,                      
        CREATE_ALWAYS,             
        FILE_ATTRIBUTE_NORMAL,     
        NULL);                     
    if (hFile == INVALID_HANDLE_VALUE)
    {
        return false;
    }
    DWORD dwBytesWrited = 0;
    WriteFile(hFile, m_pNewPe, m_nNewPe, &dwBytesWrited, NULL);
    return true;
}

BOOL CPacker::AddDllShell(CString strPath)
{
    //����PE
    if (!AnalyzePe(strPath))
    {
        return FALSE;
    }
    //���ܴ����
    EncryptCode();
    //������PE
    //����ڱ�
    m_nNewSecTable = sizeof(IMAGE_SECTION_HEADER) * (NUM_SECTION + 1);
    m_pNewSecTable = new IMAGE_SECTION_HEADER[NUM_SECTION + 1];
    ZeroMemory(m_pNewSecTable, m_nNewSecTable);
    //1.�ս�
    strcpy((char*)m_pNewSecTable[0].Name, ".zyx");
    m_pNewSecTable[0].Misc.VirtualSize = m_pNtHdr->OptionalHeader.SizeOfImage;
    m_pNewSecTable[0].VirtualAddress = m_pSecHdrs[0].VirtualAddress;
    m_pNewSecTable[0].SizeOfRawData = 0;   //�ս�û���ļ���С
    m_pNewSecTable[0].PointerToRawData = 0;
    m_pNewSecTable[0].Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;  //�ɶ���д��ִ��
    //2.���ܹ����Դ�����
    strcpy((char*)m_pNewSecTable[1].Name, ".data");
    m_pNewSecTable[1].Misc.VirtualSize = m_pNtHdr->OptionalHeader.SizeOfImage;
    m_pNewSecTable[1].VirtualAddress = m_pNewSecTable[0].VirtualAddress + m_pNewSecTable[0].Misc.VirtualSize;
    m_pNewSecTable[1].SizeOfRawData = GetAlign(m_nFileSize, m_pNtHdr->OptionalHeader.FileAlignment);
    m_pNewSecTable[1].PointerToRawData = m_pNtHdr->OptionalHeader.SizeOfHeaders;
    m_pNewSecTable[1].Characteristics = IMAGE_SCN_MEM_READ;
    //3.���ܼ��ؽ�
    strcpy((char*)m_pNewSecTable[2].Name, ".code");
    m_pNewSecTable[2].Misc.VirtualSize = GetAlign(CODE_DECRYPT, m_pNtHdr->OptionalHeader.SectionAlignment);
    m_pNewSecTable[2].VirtualAddress = m_pNewSecTable[1].VirtualAddress + m_pNewSecTable[1].Misc.VirtualSize;
    m_pNewSecTable[2].SizeOfRawData = GetAlign(CODE_DECRYPT, m_pNtHdr->OptionalHeader.FileAlignment);
    m_pNewSecTable[2].PointerToRawData = m_pNewSecTable[1].PointerToRawData + m_pNewSecTable[1].SizeOfRawData;
    m_pNewSecTable[2].Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;  //�ɶ���ִ��
    //4.��Դ��
    IMAGE_DATA_DIRECTORY res = m_pNtHdr->OptionalHeader.DataDirectory[2];
    strcpy((char*)m_pNewSecTable[3].Name, ".rsrc");
    m_pNewSecTable[3].Misc.VirtualSize = GetAlign(res.Size, m_pNtHdr->OptionalHeader.SectionAlignment);
    m_pNewSecTable[3].VirtualAddress = m_pNewSecTable[2].VirtualAddress + m_pNewSecTable[2].Misc.VirtualSize;
    m_pNewSecTable[3].SizeOfRawData = GetAlign(res.Size, m_pNtHdr->OptionalHeader.FileAlignment);
    m_pNewSecTable[3].PointerToRawData = m_pNewSecTable[2].PointerToRawData + m_pNewSecTable[2].SizeOfRawData;
    m_pNewSecTable[3].Characteristics = 0x40000040;  //�ɶ�
    //����PEͷ
    m_nNewHdrPeSize = m_pNtHdr->OptionalHeader.SizeOfHeaders;
    m_pNewPeHdr = new BYTE[m_nNewHdrPeSize];
    memcpy(m_pNewPeHdr, m_pPeBuff, m_nNewHdrPeSize);
    PIMAGE_DOS_HEADER pDosHdr = (PIMAGE_DOS_HEADER)m_pNewPeHdr;
    PIMAGE_NT_HEADERS pNtHdr = (PIMAGE_NT_HEADERS)(m_pNewPeHdr + m_pDosHdr->e_lfanew);
    PIMAGE_SECTION_HEADER pSecHdrs = (PIMAGE_SECTION_HEADER)((uint8_t*)&pNtHdr->OptionalHeader + pNtHdr->FileHeader.SizeOfOptionalHeader);
    //�޸Ľڱ���Ŀ
    pNtHdr->FileHeader.NumberOfSections = NUM_SECTION;
    //�޸���ڵ�
    pNtHdr->OptionalHeader.AddressOfEntryPoint = m_pNewSecTable[2].VirtualAddress;
    //�޸����ڴ���ܴ�С  
    pNtHdr->OptionalHeader.SizeOfImage = m_pNewSecTable[NUM_SECTION - 1].VirtualAddress + m_pNewSecTable[NUM_SECTION - 1].Misc.VirtualSize; //���һ���ڵĵ�ַ + ��С

    //�޸�����Ŀ¼
    ZeroMemory(pNtHdr->OptionalHeader.DataDirectory, sizeof(pNtHdr->OptionalHeader.DataDirectory));
    pNtHdr->OptionalHeader.DataDirectory[2].VirtualAddress = m_pNewSecTable[3].VirtualAddress;
    pNtHdr->OptionalHeader.DataDirectory[2].Size = res.Size;
    //�����ڱ�
    CopyMemory(pSecHdrs, m_pNewSecTable, m_nNewSecTable);

    //�����µ�PE�ļ�
    m_nNewPe = m_pNewSecTable[NUM_SECTION - 1].PointerToRawData + m_pNewSecTable[NUM_SECTION - 1].SizeOfRawData;
    m_pNewPe = new BYTE[m_nNewPe];
    ZeroMemory(m_pNewPe, m_nNewPe);
    //���PEͷ
    CopyMemory(m_pNewPe, m_pNewPeHdr, m_nNewHdrPeSize);
    //�����ܹ��Ĵ����
    CopyMemory(m_pNewPe + m_pNewSecTable[1].PointerToRawData, m_pEnCode, m_nEnCodeSize);
    //�����ܲ���
    CopyMemory(m_pNewPe + m_pNewSecTable[2].PointerToRawData, m_pDllCode, m_nDllCode);
    //�����Դ��
    DWORD FOA_res = RVA2FOA(res.VirtualAddress);
    if (FOA_res != 0)
    {
        CopyMemory(m_pNewPe + m_pNewSecTable[3].PointerToRawData, m_pPeBuff + FOA_res, res.Size);
        //�޸���Դ��
        RepairResource((PIMAGE_RESOURCE_DIRECTORY)(m_pNewPe + m_pNewSecTable[3].PointerToRawData));
    }
    CString strDstPath = strPath.Left(strPath.ReverseFind('.')) + "_pack" + "." + "dll";

    HANDLE hFile = CreateFile(strDstPath,
        GENERIC_WRITE,
        FILE_SHARE_READ,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        return false;
    }
    DWORD dwBytesWrited = 0;
    WriteFile(hFile, m_pNewPe, m_nNewPe, &dwBytesWrited, NULL);
    return TRUE;
}

BOOL CPacker::DecShell(CString strPath)
{
    //����PE
    if (!AnalyzePe(strPath))
    {
        return FALSE;
    }
    DecryptCode();
    CString strDstPath = strPath.Left(strPath.Find(".")) + "_unpack" + "." + strPath.Right(strPath.GetLength() - strPath.Find(".") - 1);
    HANDLE hFile = CreateFile(strDstPath,
        GENERIC_WRITE,
        FILE_SHARE_READ,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        return false;
    }
    DWORD dwBytesWrited = 0;
    WriteFile(hFile, m_pDeCode, m_nDeCodeSize, &dwBytesWrited, NULL);
    return true;
    return 0;
}

DWORD CPacker::GetAlign(DWORD dwValue, DWORD dwAlign)
{

    return dwValue % dwAlign == 0 ? dwValue : (dwValue / dwAlign + 1) * dwAlign;
}

BOOL CPacker::AnalyzePe(CString strPath)
{
    HANDLE hFile = CreateFile(strPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, 0);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        return FALSE;
    }
    m_nFileSize = GetFileSize(hFile, NULL);

    HANDLE hMapFile = CreateFileMapping(hFile,
        NULL,
        PAGE_READONLY,
        0,
        0,
        NULL);

    if (hMapFile == NULL)
    {
        return false;
    }
    m_pPeBuff = (uint8_t*)MapViewOfFile(hMapFile,
        FILE_MAP_READ,
        0,
        0,
        0);
    if (m_pPeBuff == NULL)
    {
        return false;
    }
    m_pDosHdr = (PIMAGE_DOS_HEADER)m_pPeBuff;
    m_pNtHdr = (PIMAGE_NT_HEADERS)(m_pPeBuff + m_pDosHdr->e_lfanew);
    m_pSecHdrs = (PIMAGE_SECTION_HEADER)((uint8_t*)&m_pNtHdr->OptionalHeader + m_pNtHdr->FileHeader.SizeOfOptionalHeader);
    m_nAlign = m_pNtHdr->OptionalHeader.FileAlignment;
    CloseHandle(hFile);
    CloseHandle(hMapFile);
    return TRUE;
}

DWORD CPacker::RVA2FOA(DWORD RVA)
{
    if (RVA <= m_pNtHdr->OptionalHeader.SizeOfHeaders)
    {
        return RVA;
    }
    else
    {
        for (int i = 0; i < m_pNtHdr->FileHeader.NumberOfSections; i++)
        {
            if ((RVA >= m_pSecHdrs[i].VirtualAddress) && (RVA <= m_pSecHdrs[i].VirtualAddress + m_pSecHdrs[i].Misc.VirtualSize))
            {
                return RVA - m_pSecHdrs[i].VirtualAddress + m_pSecHdrs[i].PointerToRawData;
            }
        }
    }
    return 0;
}

BOOL CPacker::RepairResource(PIMAGE_RESOURCE_DIRECTORY pRsrcDir)
{
    int nCountByType = pRsrcDir->NumberOfIdEntries + pRsrcDir->NumberOfNamedEntries;
    IMAGE_RESOURCE_DIRECTORY_ENTRY* pRsrcEntry = (IMAGE_RESOURCE_DIRECTORY_ENTRY*)((DWORD)pRsrcDir + sizeof(*pRsrcDir));

    for (int i = 0; i < nCountByType; ++i, ++pRsrcEntry)
    {
        if (pRsrcEntry->DataIsDirectory)
        {
            //Ŀ¼
            IMAGE_RESOURCE_DIRECTORY* pNextRsrcDir = (IMAGE_RESOURCE_DIRECTORY*)(m_pNewPe+m_pNewSecTable[3].PointerToRawData + pRsrcEntry->OffsetToDirectory);


            RepairResource(pNextRsrcDir);
        }
        else
        {
            //�ļ�

            IMAGE_RESOURCE_DATA_ENTRY* pNextRsrcDir = (IMAGE_RESOURCE_DATA_ENTRY*)(m_pNewPe + m_pNewSecTable[3].PointerToRawData + pRsrcEntry->OffsetToDirectory);

            //�޸�
            pNextRsrcDir->OffsetToData =pNextRsrcDir->OffsetToData - m_pNtHdr->OptionalHeader.DataDirectory[2].VirtualAddress + m_pNewSecTable[3].VirtualAddress;
        }

    }
    return true;
}

uint8_t* CPacker::EncryptCode()
{
    m_nEnCodeSize = GetAlign(m_nFileSize, m_nAlign);
    m_pEnCode = new BYTE[m_nEnCodeSize];
    memcpy(m_pEnCode, m_pPeBuff, m_nFileSize);
    //����
    for (int i = 0; i < m_nFileSize; i++)
    {
        m_pEnCode[i] ^= 0x31;
    }
    return m_pEnCode;
}

uint8_t* CPacker::DecryptCode()
{
    m_nDeCodeSize = m_pSecHdrs[1].SizeOfRawData;
    m_pDeCode = new BYTE[m_nDeCodeSize];
    memcpy(m_pDeCode, m_pPeBuff+ m_pSecHdrs[1].PointerToRawData, m_nDeCodeSize);
    //����
    for (int i = 0; i < m_nDeCodeSize; i++)
    {
        m_pDeCode[i] ^= 0x31;
    }
    return m_pDeCode;
}

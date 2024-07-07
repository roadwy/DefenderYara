
rule Trojan_Win64_Meterpreter_EB_MTB{
	meta:
		description = "Trojan:Win64/Meterpreter.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {57 69 6e 53 6f 63 6b 20 32 2e 30 } //1 WinSock 2.0
		$a_01_1 = {4d 50 47 6f 6f 64 53 74 61 74 75 73 } //1 MPGoodStatus
		$a_01_2 = {77 73 32 5f 33 32 } //1 ws2_32
		$a_01_3 = {41 51 41 50 52 51 56 48 31 } //1 AQAPRQVH1
		$a_01_4 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //1 VirtualAllocEx
		$a_01_5 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
		$a_01_6 = {43 72 65 61 74 65 53 65 6d 61 70 68 6f 72 65 41 } //1 CreateSemaphoreA
		$a_01_7 = {59 5a 41 58 41 59 41 5a 48 } //1 YZAXAYAZH
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}
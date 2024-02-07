
rule Trojan_Win32_Emotet_DWTD_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DWTD!MTB,SIGNATURE_TYPE_PEHSTR,19 00 19 00 09 00 00 0a 00 "
		
	strings :
		$a_01_0 = {56 7a 63 73 53 78 64 4b 6f 70 54 64 66 43 56 53 } //0a 00  VzcsSxdKopTdfCVS
		$a_01_1 = {44 61 78 63 7a 73 64 65 72 46 47 76 75 6a 2e 65 78 65 } //0a 00  DaxczsderFGvuj.exe
		$a_01_2 = {45 6d 6f 74 69 63 2e 65 78 65 } //0a 00  Emotic.exe
		$a_01_3 = {5a 4e 71 7a 58 47 47 73 76 77 4c 6d } //01 00  ZNqzXGGsvwLm
		$a_01_4 = {6d 00 65 00 6d 00 63 00 70 00 79 00 } //01 00  memcpy
		$a_01_5 = {4c 00 6f 00 63 00 6b 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 } //01 00  LockResource
		$a_01_6 = {43 00 72 00 79 00 70 00 74 00 41 00 63 00 71 00 75 00 69 00 72 00 65 00 43 00 6f 00 6e 00 74 00 65 00 78 00 74 00 57 00 } //01 00  CryptAcquireContextW
		$a_01_7 = {56 00 69 00 72 00 74 00 75 00 61 00 6c 00 41 00 6c 00 6c 00 6f 00 63 00 } //01 00  VirtualAlloc
		$a_01_8 = {43 00 72 00 79 00 70 00 74 00 45 00 6e 00 63 00 72 00 79 00 70 00 74 00 } //00 00  CryptEncrypt
	condition:
		any of ($a_*)
 
}
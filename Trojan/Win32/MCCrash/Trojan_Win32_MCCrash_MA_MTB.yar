
rule Trojan_Win32_MCCrash_MA_MTB{
	meta:
		description = "Trojan:Win32/MCCrash.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 "
		
	strings :
		$a_03_0 = {6a 00 6a 02 6a 02 6a 00 6a 02 68 00 00 00 40 8d 45 a0 8b 0d 84 46 40 00 8b 15 8c 46 40 00 e8 90 01 04 8b 45 a0 e8 90 01 04 50 e8 90 00 } //5
		$a_01_1 = {8b 13 85 d2 74 19 c7 03 00 00 00 00 8b 4a f8 49 7c 0d ff 4a f8 75 08 8d 42 f8 e8 63 fa ff ff 83 c3 04 4e 75 db } //5
		$a_01_2 = {4c 6f 63 6b 52 65 73 6f 75 72 63 65 } //1 LockResource
		$a_01_3 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 57 } //1 URLDownloadToFileW
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=12
 
}
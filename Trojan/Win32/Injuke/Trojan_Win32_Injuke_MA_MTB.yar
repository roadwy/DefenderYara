
rule Trojan_Win32_Injuke_MA_MTB{
	meta:
		description = "Trojan:Win32/Injuke.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 "
		
	strings :
		$a_01_0 = {8b 4c 24 10 8b 15 7c 7e 48 00 50 51 52 6a 00 ff 15 7c 07 47 00 6a 00 6a 00 ff 15 54 04 47 00 6a 00 ff 15 64 07 47 00 e8 ff 26 ff ff 31 05 a0 4c 47 00 ff 15 } //5
		$a_01_1 = {47 00 4e 00 53 00 65 00 61 00 72 00 63 00 68 00 2e 00 65 00 78 00 65 00 } //5 GNSearch.exe
		$a_01_2 = {47 65 74 54 69 63 6b 43 6f 75 6e 74 } //1 GetTickCount
		$a_01_3 = {43 72 65 61 74 65 4d 75 74 65 78 57 } //1 CreateMutexW
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=12
 
}
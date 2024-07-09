
rule Backdoor_Win32_Afcore_M{
	meta:
		description = "Backdoor:Win32/Afcore.M,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_03_0 = {f3 a4 c7 07 2e 64 ?? 6c c6 47 04 00 6a 01 68 00 00 00 c0 } //2
		$a_01_1 = {83 c3 07 8b 45 0c 89 45 fc 6a 10 8d 4d f0 b8 78 56 34 12 } //2
		$a_03_2 = {74 0a d1 e9 81 f1 ?? ?? ?? ?? eb 02 d1 e9 4e 75 } //2
		$a_01_3 = {ff ff 80 bd eb fe ff ff 61 72 06 6a 7a 6a 61 eb 04 6a 5a 6a 41 } //1
		$a_01_4 = {6a 40 ff 75 f0 ff d6 6a f1 ff 75 f4 ff d7 ff 75 f4 } //1
		$a_01_5 = {41 46 43 4f 52 45 5f 42 41 53 45 } //1 AFCORE_BASE
		$a_01_6 = {2a 5c 69 6e 74 65 72 6e 2a 5c 69 65 78 70 6c 6f 72 65 2e 65 78 65 } //1 *\intern*\iexplore.exe
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_03_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=5
 
}

rule Trojan_Win32_Upatre_ME_MTB{
	meta:
		description = "Trojan:Win32/Upatre.ME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {83 c4 10 56 68 80 00 00 00 6a 03 56 6a 01 68 00 00 00 80 53 ff 15 } //1
		$a_01_1 = {8b 4d f8 8d 44 41 04 50 ff 75 e4 ff 75 ec ff 15 } //1
		$a_01_2 = {3a 00 5c 00 54 00 45 00 4d 00 50 00 5c 00 73 00 61 00 6d 00 68 00 65 00 2e 00 65 00 78 00 65 00 } //1 :\TEMP\samhe.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}

rule Trojan_Win32_FileCoder_ARAX_MTB{
	meta:
		description = "Trojan:Win32/FileCoder.ARAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8d 55 e0 03 d0 40 8a 0c 13 32 0a 88 0c 16 3b c7 72 ee } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
rule Trojan_Win32_FileCoder_ARAX_MTB_2{
	meta:
		description = "Trojan:Win32/FileCoder.ARAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 14 07 32 10 ff 85 c4 fd ff ff 88 14 01 33 d2 40 3b d6 72 eb } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
rule Trojan_Win32_FileCoder_ARAX_MTB_3{
	meta:
		description = "Trojan:Win32/FileCoder.ARAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {41 d1 eb 83 e8 01 89 4d fc 89 45 f4 0f 85 6b ff ff ff } //2
		$a_00_1 = {47 00 6c 00 6f 00 62 00 61 00 6c 00 5c 00 46 00 53 00 57 00 69 00 70 00 65 00 72 00 } //2 Global\FSWiper
		$a_00_2 = {5c 00 5a 00 4c 00 57 00 50 00 2e 00 74 00 6d 00 70 00 } //2 \ZLWP.tmp
	condition:
		((#a_01_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2) >=6
 
}
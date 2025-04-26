
rule Trojan_Win32_CobaltStrike_LKAK_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.LKAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {76 1d 0f b6 fa 83 ef 11 8d 4e 01 83 ff 04 0f 82 aa 00 00 00 8a 11 88 10 40 41 4f 75 f7 } //1
		$a_01_1 = {8a 17 88 10 8a 57 01 88 50 01 8a 57 02 41 88 50 02 83 c0 03 8b de 0f b6 79 ff 83 e7 03 } //1
		$a_01_2 = {6a 40 68 00 10 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}

rule Trojan_Win32_Chebri_B{
	meta:
		description = "Trojan:Win32/Chebri.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {c6 45 fc 21 8a 4d 10 88 4d fd 6a 06 8d 55 f8 52 8b 45 08 50 e8 } //1
		$a_03_1 = {68 21 4e 00 00 68 90 01 04 e8 90 01 04 83 c4 90 01 01 ba 01 00 00 00 85 d2 74 0d 90 00 } //1
		$a_01_2 = {44 41 4e 43 48 4f 44 41 4e 43 48 45 56 5f 41 4e 44 5f 42 52 49 41 4e 4b 52 45 42 53 5f 47 4f 54 5f 4d 41 52 52 49 45 44 } //1 DANCHODANCHEV_AND_BRIANKREBS_GOT_MARRIED
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
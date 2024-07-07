
rule Trojan_Win32_Rolnoxo_A{
	meta:
		description = "Trojan:Win32/Rolnoxo.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {e9 ca 00 00 00 8d bd 64 fd ff ff 4f 8a 47 01 47 3a c3 75 f8 be 90 01 02 40 00 a5 66 a5 33 c0 8d 7d cc ab ab 6a 11 ab 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Rolnoxo_A_2{
	meta:
		description = "Trojan:Win32/Rolnoxo.A,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {83 e8 0a 89 46 06 8d 45 fc 50 c6 06 55 c7 46 01 8b ec eb 05 c6 46 05 e9 ff 75 fc 6a 0a 56 ff d7 89 35 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
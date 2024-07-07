
rule Trojan_Win32_Fragtor_KAA_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.KAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {21 d2 8b 06 ba 90 01 04 81 c1 90 01 04 81 e9 90 01 04 81 e0 90 01 04 4a f7 d7 31 03 81 c7 e8 2c e5 ef 29 f9 4a 43 09 d2 49 46 89 fa 21 d1 4f 81 fb 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
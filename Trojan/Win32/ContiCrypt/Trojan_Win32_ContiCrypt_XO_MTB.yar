
rule Trojan_Win32_ContiCrypt_XO_MTB{
	meta:
		description = "Trojan:Win32/ContiCrypt.XO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 19 8d 34 10 02 da 42 30 1e 83 fa } //01 00 
		$a_01_1 = {0f b7 c0 0f 47 d0 83 c1 02 0f b7 c2 43 33 f0 89 4d f8 } //00 00 
	condition:
		any of ($a_*)
 
}
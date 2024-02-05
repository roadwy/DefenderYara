
rule Trojan_Win32_Doina_GMG_MTB{
	meta:
		description = "Trojan:Win32/Doina.GMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 04 00 00 0a 00 "
		
	strings :
		$a_01_0 = {0f b6 da 80 c3 98 80 75 0c 20 8d 64 24 04 66 0f b6 d8 } //0a 00 
		$a_01_1 = {fe c6 80 e2 0b 8a 06 d2 f2 d0 c2 28 d8 3c c4 } //01 00 
		$a_01_2 = {47 6d 58 4f 6a 6b 4a 4a } //01 00 
		$a_01_3 = {50 2e 76 6d 70 30 } //00 00 
	condition:
		any of ($a_*)
 
}
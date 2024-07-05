
rule Trojan_Win32_Lazy_HND_MTB{
	meta:
		description = "Trojan:Win32/Lazy.HND!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {c6 44 24 27 2f c6 44 24 28 34 c6 44 24 29 2e c6 44 24 2a 30 c6 44 24 2b 20 c6 44 24 2c 28 c6 44 24 2d 63 } //01 00 
		$a_01_1 = {8b 45 fc ff 45 fc 8a 18 } //01 00 
		$a_01_2 = {c6 44 24 22 7a 88 54 24 23 88 4c 24 26 } //01 00 
		$a_01_3 = {b9 00 01 00 00 33 c0 8d 7c 24 38 } //00 00 
	condition:
		any of ($a_*)
 
}
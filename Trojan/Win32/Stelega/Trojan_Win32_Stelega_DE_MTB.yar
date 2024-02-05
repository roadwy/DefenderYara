
rule Trojan_Win32_Stelega_DE_MTB{
	meta:
		description = "Trojan:Win32/Stelega.DE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {b8 39 8e e3 38 f7 eb c1 fa 02 8b c2 c1 e8 1f 03 c2 8a c8 c0 e0 03 02 c8 8a c3 02 c9 2a c1 04 05 32 c5 88 04 1e 43 8a 2c 3b 84 ed 75 } //01 00 
		$a_81_1 = {65 6e 63 72 79 70 74 65 64 5f 6b 65 79 } //01 00 
		$a_81_2 = {46 74 62 69 7d 6f 4d 65 61 6b 42 71 61 62 7a 7a 72 41 } //00 00 
	condition:
		any of ($a_*)
 
}
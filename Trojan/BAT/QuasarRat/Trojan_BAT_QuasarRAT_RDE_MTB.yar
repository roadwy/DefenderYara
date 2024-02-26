
rule Trojan_BAT_QuasarRAT_RDE_MTB{
	meta:
		description = "Trojan:BAT/QuasarRAT.RDE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {31 38 37 62 33 62 31 32 2d 31 38 35 64 2d 34 63 61 38 2d 62 31 39 38 2d 66 38 66 66 66 30 31 30 35 37 32 37 } //01 00  187b3b12-185d-4ca8-b198-f8fff0105727
		$a_01_1 = {42 54 43 20 43 6c 69 70 70 65 72 } //01 00  BTC Clipper
		$a_01_2 = {44 65 63 6f 6d 70 72 65 73 73 } //01 00  Decompress
		$a_01_3 = {44 65 63 72 79 70 74 } //00 00  Decrypt
	condition:
		any of ($a_*)
 
}

rule Trojan_BAT_QuasarRAT_L_MTB{
	meta:
		description = "Trojan:BAT/QuasarRAT.L!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {57 95 02 28 c9 03 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 2e 00 00 00 0c 00 00 00 2b 00 00 00 36 } //02 00 
		$a_01_1 = {4c 7a 6d 61 44 65 63 6f 64 65 72 } //02 00  LzmaDecoder
		$a_01_2 = {42 69 74 44 65 63 6f 64 65 72 } //00 00  BitDecoder
	condition:
		any of ($a_*)
 
}

rule Trojan_BAT_LummaC_GZZ_MTB{
	meta:
		description = "Trojan:BAT/LummaC.GZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {8f 1b 00 00 01 25 71 1b 00 00 01 1f 2e 58 d2 81 1b 00 00 01 } //01 00 
		$a_80_1 = {49 4b 6e 6b 63 6e 6a 62 7a 6a 5a 42 6f 61 61 } //IKnkcnjbzjZBoaa  00 00 
	condition:
		any of ($a_*)
 
}

rule Trojan_BAT_Redline_NEAT_MTB{
	meta:
		description = "Trojan:BAT/Redline.NEAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {28 32 00 00 06 0a 28 18 00 00 06 0b 07 1f 20 8d 13 00 00 01 25 d0 31 00 00 04 28 0f 00 00 0a 6f 73 00 00 0a 07 1f 10 8d 13 00 00 01 25 d0 35 00 00 04 28 0f 00 00 0a 6f 74 00 00 0a 06 07 6f 75 00 00 0a 17 73 4e 00 00 0a 25 02 16 02 8e 69 } //05 00 
		$a_01_1 = {53 63 61 6e 50 72 6f 63 65 73 73 65 73 2e 65 78 65 } //00 00 
	condition:
		any of ($a_*)
 
}
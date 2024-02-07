
rule Trojan_BAT_NjRat_NEAT_MTB{
	meta:
		description = "Trojan:BAT/NjRat.NEAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {0c 07 08 7e 06 00 00 04 6f 20 00 00 0a 28 21 00 00 0a de 0a 08 2c 06 08 6f 22 00 00 0a dc 07 } //05 00 
		$a_01_1 = {6c 00 61 00 74 00 69 00 6e 00 2d 00 65 00 2e 00 63 00 6f 00 6d 00 } //00 00  latin-e.com
	condition:
		any of ($a_*)
 
}
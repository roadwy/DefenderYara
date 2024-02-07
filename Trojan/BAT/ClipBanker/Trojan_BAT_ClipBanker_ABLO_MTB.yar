
rule Trojan_BAT_ClipBanker_ABLO_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.ABLO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {50 6f 6b 65 6d 6f 6e 53 79 73 74 65 6d 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //01 00  PokemonSystem.Resources.resources
		$a_01_1 = {50 00 6f 00 6b 00 65 00 6d 00 6f 00 6e 00 53 00 79 00 73 00 74 00 65 00 6d 00 } //00 00  PokemonSystem
	condition:
		any of ($a_*)
 
}
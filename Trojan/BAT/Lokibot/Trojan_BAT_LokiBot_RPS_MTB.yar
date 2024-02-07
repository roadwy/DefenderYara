
rule Trojan_BAT_LokiBot_RPS_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.RPS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {d2 9c 00 09 17 58 0d 09 17 fe 04 13 04 11 04 2d c5 06 17 58 0a 00 08 17 58 0c 08 90 01 05 fe 04 13 05 11 05 2d a9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_LokiBot_RPS_MTB_2{
	meta:
		description = "Trojan:BAT/LokiBot.RPS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {37 00 36 00 34 00 38 00 48 00 32 00 38 00 } //01 00  7648H28
		$a_01_1 = {46 00 35 00 45 00 4a 00 34 00 38 00 46 00 46 00 47 00 48 00 55 00 35 00 35 00 54 00 36 00 } //01 00  F5EJ48FFGHU55T6
		$a_01_2 = {38 00 33 00 37 00 34 00 37 00 } //01 00  83747
		$a_01_3 = {4c 6f 6f 70 53 74 61 74 65 33 32 } //01 00  LoopState32
		$a_01_4 = {47 00 61 00 6d 00 65 00 46 00 6f 00 72 00 53 00 65 00 6d 00 65 00 73 00 74 00 72 00 } //00 00  GameForSemestr
	condition:
		any of ($a_*)
 
}
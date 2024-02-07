
rule Trojan_BAT_Remcos_AOO_MTB{
	meta:
		description = "Trojan:BAT/Remcos.AOO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {16 0d 2b 13 00 07 09 06 09 9a 1f 10 28 50 00 00 0a 9c 00 09 17 58 0d 09 06 8e 69 fe 04 13 04 11 04 2d e1 } //01 00 
		$a_01_1 = {42 00 6c 00 61 00 63 00 6b 00 4a 00 61 00 63 00 6b 00 41 00 6b 00 61 00 73 00 68 00 } //00 00  BlackJackAkash
	condition:
		any of ($a_*)
 
}
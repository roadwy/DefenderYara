
rule Trojan_BAT_Discord_ARA_MTB{
	meta:
		description = "Trojan:BAT/Discord.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {02 07 02 8e b7 5d 02 07 02 8e b7 5d 91 03 07 03 8e b7 5d 91 61 02 07 17 d6 02 8e b7 5d 91 da 20 00 01 00 00 d6 20 00 01 00 00 5d b4 9c 07 15 d6 0b 07 16 2f cb } //00 00 
	condition:
		any of ($a_*)
 
}
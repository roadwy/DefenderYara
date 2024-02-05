
rule Trojan_BAT_Remcos_PH_MTB{
	meta:
		description = "Trojan:BAT/Remcos.PH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {72 01 00 00 70 72 90 01 03 70 28 02 00 00 06 74 01 00 00 1b 0a 72 90 01 03 70 28 10 00 00 0a 0b 16 0c 2b 13 06 08 06 08 91 07 08 07 8e 69 5d 91 61 d2 9c 08 17 58 0c 08 06 8e 69 32 e7 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
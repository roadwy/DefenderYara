
rule Trojan_BAT_Amadey_MA_MTB{
	meta:
		description = "Trojan:BAT/Amadey.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {11 06 11 04 16 11 04 8e 69 28 90 01 02 00 06 13 07 38 00 00 00 00 11 07 13 00 38 00 00 00 00 dd d6 00 00 00 00 11 06 3a 05 00 00 00 38 0c 00 00 00 11 06 28 90 01 02 00 06 38 0a 00 00 00 38 06 00 00 00 38 ea ff ff ff 00 dc 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
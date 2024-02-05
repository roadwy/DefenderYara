
rule Trojan_Win64_Emotet_RPA_MTB{
	meta:
		description = "Trojan:Win64/Emotet.RPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {42 0f b6 14 09 44 8b 55 a8 41 31 d2 45 88 d3 48 8b 8d b0 0b 00 00 4c 63 4d fc 46 88 1c 09 8b 45 fc 83 c0 01 89 45 fc e9 } //00 00 
	condition:
		any of ($a_*)
 
}
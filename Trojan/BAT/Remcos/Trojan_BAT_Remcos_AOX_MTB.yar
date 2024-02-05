
rule Trojan_BAT_Remcos_AOX_MTB{
	meta:
		description = "Trojan:BAT/Remcos.AOX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {07 11 04 17 73 94 00 00 0a 0c 28 90 01 03 06 16 9a 75 19 00 00 1b 0d 08 09 16 09 8e 69 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
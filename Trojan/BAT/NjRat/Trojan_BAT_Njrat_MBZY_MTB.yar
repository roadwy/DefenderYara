
rule Trojan_BAT_Njrat_MBZY_MTB{
	meta:
		description = "Trojan:BAT/Njrat.MBZY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {4d 00 dc 05 dc 05 5a 00 dc 05 dc 05 90 00 dc 05 dc 05 00 00 dc 05 dc 05 03 00 dc 05 dc 05 00 00 dc 05 dc 05 00 00 dc 05 dc 05 } //00 00 
	condition:
		any of ($a_*)
 
}
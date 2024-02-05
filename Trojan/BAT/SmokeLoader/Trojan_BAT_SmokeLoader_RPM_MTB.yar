
rule Trojan_BAT_SmokeLoader_RPM_MTB{
	meta:
		description = "Trojan:BAT/SmokeLoader.RPM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {7e 05 00 00 04 20 17 01 00 00 28 af 00 00 06 7e 05 00 00 04 20 17 01 00 00 28 af 00 00 06 28 73 00 00 06 0c 02 28 69 00 00 06 08 02 7e 05 00 00 04 20 17 01 00 00 28 af 00 00 06 28 61 00 00 06 0c 14 } //00 00 
	condition:
		any of ($a_*)
 
}
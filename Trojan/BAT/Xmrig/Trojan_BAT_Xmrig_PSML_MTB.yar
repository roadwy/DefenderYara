
rule Trojan_BAT_Xmrig_PSML_MTB{
	meta:
		description = "Trojan:BAT/Xmrig.PSML!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {11 05 11 08 9a 72 ee 00 00 70 6f 1e 00 00 0a 2c 0c 11 05 11 08 72 fe 00 00 70 a2 2b 4b 11 05 11 08 9a 72 2a 01 00 70 6f 1e 00 00 0a 2c 0c 11 05 11 08 72 38 01 00 70 } //00 00 
	condition:
		any of ($a_*)
 
}
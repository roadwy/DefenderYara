
rule Trojan_BAT_Loki_NEAB_MTB{
	meta:
		description = "Trojan:BAT/Loki.NEAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {00 00 0a 73 01 00 00 06 28 04 00 00 06 6f 90 01 01 00 00 0a 90 01 01 2d 04 26 26 2b 07 90 00 } //05 00 
		$a_03_1 = {07 03 08 18 6f 90 01 01 00 00 0a 1f 10 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 08 18 58 0c 08 06 32 e3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
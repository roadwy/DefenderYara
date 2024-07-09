
rule Trojan_BAT_Njrat_LS_MTB{
	meta:
		description = "Trojan:BAT/Njrat.LS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 16 fe 01 5f 07 17 5f 17 fe 01 5f ?? ?? ?? ?? ?? 16 fe 01 06 16 fe 01 16 fe 01 5f 07 17 5f 17 fe 01 5f 60 0c 11 06 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
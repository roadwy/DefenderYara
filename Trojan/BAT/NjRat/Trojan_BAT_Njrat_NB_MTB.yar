
rule Trojan_BAT_Njrat_NB_MTB{
	meta:
		description = "Trojan:BAT/Njrat.NB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {1f 6f 91 61 1f ?? 5f 9c } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
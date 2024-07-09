
rule Trojan_BAT_Bladabindi_GPA_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.GPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 84 95 11 ?? 08 84 95 d7 6e 20 ?? ?? 00 00 6a 5f b7 95 61 86 9c 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}

rule Trojan_BAT_Bladabindi_PTFM_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.PTFM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {72 c5 00 00 70 6f 04 00 00 0a 28 90 01 01 00 00 06 28 90 01 01 00 00 0a 6f 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}

rule Backdoor_BAT_Bladabindi_KAAB_MTB{
	meta:
		description = "Backdoor:BAT/Bladabindi.KAAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {59 61 d2 61 d2 81 ?? 00 00 01 11 07 17 58 13 07 1e 13 09 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}

rule Backdoor_BAT_Bladabindi_KAO_MTB{
	meta:
		description = "Backdoor:BAT/Bladabindi.KAO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {09 11 06 03 11 06 91 08 61 07 11 04 91 61 b4 9c } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}

rule Backdoor_BAT_Bladabindi_KAZ_MTB{
	meta:
		description = "Backdoor:BAT/Bladabindi.KAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {08 06 02 06 91 11 04 61 09 07 91 61 b4 9c } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
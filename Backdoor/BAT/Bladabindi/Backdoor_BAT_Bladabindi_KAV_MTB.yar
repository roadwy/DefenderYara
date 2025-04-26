
rule Backdoor_BAT_Bladabindi_KAV_MTB{
	meta:
		description = "Backdoor:BAT/Bladabindi.KAV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {09 06 16 11 04 6f ?? 00 00 0a 00 07 06 16 06 8e b7 6f ?? 00 00 0a 13 04 00 11 04 16 fe 02 13 06 11 06 2d dc } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
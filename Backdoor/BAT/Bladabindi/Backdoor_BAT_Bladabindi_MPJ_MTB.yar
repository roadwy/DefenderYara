
rule Backdoor_BAT_Bladabindi_MPJ_MTB{
	meta:
		description = "Backdoor:BAT/Bladabindi.MPJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {13 06 11 06 28 90 01 04 0c 08 28 90 01 09 0d 09 28 90 01 09 16 8c 90 01 04 14 6f 90 01 04 26 2a 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
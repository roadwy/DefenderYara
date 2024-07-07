
rule Backdoor_BAT_Bladabindi_MI_MTB{
	meta:
		description = "Backdoor:BAT/Bladabindi.MI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0b 06 07 28 90 01 13 0c 08 6f 90 01 04 16 9a 0d 09 6f 90 01 04 16 9a 13 04 73 90 01 09 11 04 14 1f 09 8d 90 01 04 25 16 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
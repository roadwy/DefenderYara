
rule Backdoor_BAT_Bladabindi_PD_MTB{
	meta:
		description = "Backdoor:BAT/Bladabindi.PD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {72 01 00 00 70 28 ?? ?? 00 0a 73 04 00 00 0a 0a 1f 1c 28 05 00 00 0a 72 0d 00 00 70 28 06 00 00 0a 06 72 2b 00 00 70 6f 07 00 00 0a 74 01 00 00 1b 28 08 00 00 0a 1f 1c 28 05 00 00 0a 72 0d 00 00 70 28 06 00 00 0a 28 09 00 00 0a 26 1f 1c 28 05 00 00 0a 72 41 00 00 70 28 06 00 00 0a 06 72 ?? ?? 00 70 6f 07 00 00 0a 74 01 00 00 1b 28 08 00 00 0a 1f 1c 28 05 00 00 0a 72 41 00 00 70 28 06 00 00 0a 28 09 00 00 0a 26 de } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
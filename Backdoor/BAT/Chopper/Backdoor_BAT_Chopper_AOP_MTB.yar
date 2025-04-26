
rule Backdoor_BAT_Chopper_AOP_MTB{
	meta:
		description = "Backdoor:BAT/Chopper.AOP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0a 25 16 9a 74 13 00 00 01 fe 0b 01 00 25 17 9a 74 14 00 00 01 fe 0b 02 00 25 18 9a 0a 26 02 6f 12 00 00 0a 28 18 00 00 0a 74 1b 00 00 01 7b 19 00 00 0a 25 16 03 a2 25 17 04 a2 25 18 06 a2 26 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}

rule Backdoor_BAT_Bladabindi_SW_MTB{
	meta:
		description = "Backdoor:BAT/Bladabindi.SW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {06 08 8f 18 00 00 02 7b 1a 00 00 04 03 33 0f 06 08 8f 18 00 00 02 7b 1b 00 00 04 0d 2b 1a 06 08 8f 18 00 00 02 7b 1b 00 00 04 2c 0c 08 17 58 0c 08 07 32 cc 16 0c 2b c8 } //2
		$a_01_1 = {53 55 50 45 52 5f 50 4f 57 45 52 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //2 SUPER_POWER.Resources.resources
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}
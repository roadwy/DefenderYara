
rule Backdoor_BAT_SpyGate_SK_MTB{
	meta:
		description = "Backdoor:BAT/SpyGate.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {03 6f 27 00 00 0a 25 26 26 08 17 58 0c 08 1a 32 ef } //2
		$a_81_1 = {35 38 65 31 30 33 66 30 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //2 58e103f0.Resources.resources
	condition:
		((#a_01_0  & 1)*2+(#a_81_1  & 1)*2) >=4
 
}

rule Backdoor_BAT_Remcos_SSK_MTB{
	meta:
		description = "Backdoor:BAT/Remcos.SSK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 0a 11 0b 58 11 0c 58 6c 17 06 19 5a 28 5d 00 00 0a 6c 5b 26 06 1f 2a 5a 20 e8 03 00 00 5d 26 11 17 17 58 13 17 } //2
		$a_01_1 = {53 74 6f 72 6d 43 61 73 74 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //2 StormCast.Properties.Resources.resources
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}
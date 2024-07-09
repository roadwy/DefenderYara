
rule Backdoor_BAT_Bladabindi_SP_MTB{
	meta:
		description = "Backdoor:BAT/Bladabindi.SP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {20 00 01 00 00 0a 7e 05 00 00 04 28 ?? ?? ?? 0a 0b 07 28 ?? ?? ?? 0a 28 ?? ?? ?? 06 6f ?? ?? ?? 0a 28 ?? ?? ?? 06 06 14 14 7e 09 00 00 04 74 01 00 00 1b 6f ?? ?? ?? 0a 26 17 28 ?? ?? ?? 0a 7e 03 00 00 04 2d ba } //4
		$a_01_1 = {67 65 74 64 65 63 72 79 70 74 69 74 } //1 getdecryptit
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}
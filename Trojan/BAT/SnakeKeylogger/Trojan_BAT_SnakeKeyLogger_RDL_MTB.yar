
rule Trojan_BAT_SnakeKeyLogger_RDL_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeyLogger.RDL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {44 41 43 6c 73 } //1 DACls
		$a_01_1 = {71 4a 4a 51 4e 79 68 4f 4a 35 47 54 74 49 32 78 6b 54 57 } //1 qJJQNyhOJ5GTtI2xkTW
		$a_01_2 = {42 67 64 54 75 52 43 72 58 53 } //1 BgdTuRCrXS
		$a_01_3 = {4e 71 53 58 63 } //1 NqSXc
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
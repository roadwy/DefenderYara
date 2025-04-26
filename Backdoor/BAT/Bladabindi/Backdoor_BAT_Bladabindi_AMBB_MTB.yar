
rule Backdoor_BAT_Bladabindi_AMBB_MTB{
	meta:
		description = "Backdoor:BAT/Bladabindi.AMBB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 16 d2 13 2c 11 16 1e 63 d1 13 16 11 1e 11 09 91 13 26 11 1e 11 09 11 26 11 24 61 11 1b 19 58 61 11 2c 61 d2 9c 11 09 17 58 13 09 11 26 13 1b } //2
		$a_01_1 = {52 65 76 65 72 73 65 } //1 Reverse
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}
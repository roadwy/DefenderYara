
rule Backdoor_BAT_Bladabindi_SS_MTB{
	meta:
		description = "Backdoor:BAT/Bladabindi.SS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {02 07 16 28 0e 00 00 06 0c 12 02 28 47 00 00 0a 0d 12 02 28 48 00 00 0a 13 04 12 02 28 49 00 00 0a 13 05 06 09 } //2
		$a_81_1 = {58 2e 6c 75 67 69 61 2e 72 65 73 6f 75 72 63 65 73 } //2 X.lugia.resources
	condition:
		((#a_01_0  & 1)*2+(#a_81_1  & 1)*2) >=4
 
}
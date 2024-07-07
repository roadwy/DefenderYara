
rule Backdoor_BAT_Bladabindi_GFF_MTB{
	meta:
		description = "Backdoor:BAT/Bladabindi.GFF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_03_0 = {11 05 11 07 02 11 07 91 11 04 11 04 07 94 11 04 08 94 58 20 ff 00 00 00 5f 94 61 28 90 01 03 0a 9c 00 11 07 17 58 13 07 90 00 } //10
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {47 65 74 43 75 72 72 65 6e 74 50 72 6f 63 65 73 73 } //1 GetCurrentProcess
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=12
 
}
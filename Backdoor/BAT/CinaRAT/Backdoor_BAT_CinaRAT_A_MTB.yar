
rule Backdoor_BAT_CinaRAT_A_MTB{
	meta:
		description = "Backdoor:BAT/CinaRAT.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {00 00 01 25 16 28 90 01 01 00 00 06 6f 90 01 02 00 06 6f 90 01 01 00 00 06 16 9a a2 25 17 28 90 01 01 00 00 06 6f 90 01 02 00 06 6f 90 01 01 00 00 06 17 9a a2 25 18 72 90 00 } //2
		$a_03_1 = {00 00 0a 1b 9a 0a 06 72 90 01 03 70 18 17 8d 90 01 01 00 00 01 25 16 72 90 01 03 70 a2 28 90 00 } //2
		$a_01_2 = {52 65 76 65 72 73 65 } //1 Reverse
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}
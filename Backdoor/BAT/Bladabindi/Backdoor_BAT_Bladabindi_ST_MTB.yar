
rule Backdoor_BAT_Bladabindi_ST_MTB{
	meta:
		description = "Backdoor:BAT/Bladabindi.ST!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {06 07 8f 1e 00 00 01 25 71 1e 00 00 01 02 07 1f 10 5d 91 61 d2 81 1e 00 00 01 07 17 58 0b 07 06 8e 69 } //2
		$a_81_1 = {4d 79 49 6d 67 75 72 20 50 72 6f 67 72 61 6d 6d 69 6e 67 20 54 65 61 6d } //2 MyImgur Programming Team
	condition:
		((#a_01_0  & 1)*2+(#a_81_1  & 1)*2) >=4
 
}
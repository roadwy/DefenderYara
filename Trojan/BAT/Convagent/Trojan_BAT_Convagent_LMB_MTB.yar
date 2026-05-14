
rule Trojan_BAT_Convagent_LMB_MTB{
	meta:
		description = "Trojan:BAT/Convagent.LMB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 03 00 00 "
		
	strings :
		$a_01_0 = {28 5d 02 00 06 2d 06 16 28 03 01 00 0a 7e 9c 02 00 04 2c 2f 17 80 9a 03 00 04 7e a4 02 00 04 25 2d 17 26 7e a3 02 00 04 fe 06 d6 01 00 06 73 61 00 00 0a 25 80 a4 02 00 04 73 62 00 00 0a 28 65 00 00 0a } //20
		$a_01_1 = {73 f0 01 00 06 80 a0 02 00 04 7e a0 02 00 04 6f e4 01 00 06 2b 2a 7e a0 02 00 04 6f df 01 00 06 2d 0a 7e a0 02 00 04 6f e7 01 00 06 73 04 01 00 0a 20 88 13 00 00 6f 05 01 00 0a 28 6a 00 00 0a 7e a1 02 00 04 2d cf 2a } //10
		$a_81_2 = {4f 66 66 4c 69 6e 65 4b 65 79 4c 6f 67 67 65 72 } //5 OffLineKeyLogger
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10+(#a_81_2  & 1)*5) >=35
 
}

rule Backdoor_BAT_AveMariaRAT_D_MTB{
	meta:
		description = "Backdoor:BAT/AveMariaRAT.D!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 06 00 00 "
		
	strings :
		$a_01_0 = {02 03 5d 0c 08 0a } //2
		$a_01_1 = {0e 04 0b 07 17 2e 05 } //2
		$a_03_2 = {00 00 04 0c 08 74 ?? 00 00 1b 25 06 93 0b 06 18 58 93 07 61 0b } //2
		$a_03_3 = {00 00 01 11 05 11 0a ?? ?? 00 00 1b 11 0c 11 07 58 11 09 59 93 61 11 0b ?? ?? 00 00 1b 11 09 11 0c 58 1f 11 58 11 08 5d 93 61 d1 6f ?? 00 00 0a 26 ?? 13 0e 38 ?? fe ff ff 11 09 17 58 13 09 ?? 13 0e 38 } //2
		$a_01_4 = {73 65 74 5f 54 69 6d 65 6f 75 74 } //1 set_Timeout
		$a_01_5 = {48 74 74 70 57 65 62 52 65 71 75 65 73 74 } //1 HttpWebRequest
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_03_2  & 1)*2+(#a_03_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=10
 
}
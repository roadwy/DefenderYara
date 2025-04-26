
rule Trojan_Win64_Tinukebot_GA_MTB{
	meta:
		description = "Trojan:Win64/Tinukebot.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {73 74 72 69 6e 67 20 74 6f 6f 20 6c 6f 6e 67 } //1 string too long
		$a_01_1 = {31 37 36 2e 31 31 31 2e 31 37 34 2e 31 34 30 } //3 176.111.174.140
		$a_01_2 = {2f 61 70 69 2e 70 68 70 } //1 /api.php
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*3+(#a_01_2  & 1)*1) >=4
 
}
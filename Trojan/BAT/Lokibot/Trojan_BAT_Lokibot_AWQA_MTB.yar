
rule Trojan_BAT_Lokibot_AWQA_MTB{
	meta:
		description = "Trojan:BAT/Lokibot.AWQA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 03 00 00 "
		
	strings :
		$a_01_0 = {07 11 05 07 11 05 94 02 5a 1f 64 5d 9e 00 11 05 17 58 13 05 } //3
		$a_01_1 = {07 11 07 07 11 07 94 03 5a 1f 64 5d 9e } //3
		$a_01_2 = {53 74 75 64 65 6e 74 5f 48 6f 75 73 69 6e 67 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //2 Student_Housing.Properties.Resources
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*2) >=8
 
}
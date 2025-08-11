
rule Trojan_BAT_VIPKeylogger_ARQA_MTB{
	meta:
		description = "Trojan:BAT/VIPKeylogger.ARQA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 04 00 00 "
		
	strings :
		$a_01_0 = {07 74 04 00 00 1b 09 07 75 04 00 00 1b 09 94 02 5a 1f 64 5d 9e 11 } //3
		$a_03_1 = {1b 11 04 07 ?? 04 00 00 1b 11 04 94 03 5a 1f 64 5d 9e } //3
		$a_03_2 = {11 07 16 28 ?? 00 00 06 13 0c 11 07 17 28 ?? 00 00 06 13 0d 11 07 18 28 ?? 00 00 06 13 0e } //2
		$a_03_3 = {03 11 0c 6f ?? 00 00 0a 03 11 0d 6f ?? 00 00 0a 03 11 0e 6f ?? 00 00 0a 06 19 58 0a } //2
	condition:
		((#a_01_0  & 1)*3+(#a_03_1  & 1)*3+(#a_03_2  & 1)*2+(#a_03_3  & 1)*2) >=10
 
}
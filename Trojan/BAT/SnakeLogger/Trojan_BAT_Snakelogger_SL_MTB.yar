
rule Trojan_BAT_Snakelogger_SL_MTB{
	meta:
		description = "Trojan:BAT/Snakelogger.SL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {00 7e 09 00 00 04 07 17 8d 21 00 00 01 25 16 02 a2 6f 4e 00 00 0a 26 00 de 05 } //2
		$a_81_1 = {53 75 70 65 72 76 69 73 6f 72 57 65 62 53 65 72 76 69 63 65 2e 65 78 65 } //2 SupervisorWebService.exe
	condition:
		((#a_01_0  & 1)*2+(#a_81_1  & 1)*2) >=4
 
}
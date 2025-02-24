
rule Trojan_BAT_Keylogger_AYA_MTB{
	meta:
		description = "Trojan:BAT/Keylogger.AYA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {72 58 01 00 70 18 28 17 00 00 0a 11 05 11 04 6f 18 00 00 0a de 0c 11 05 2c 07 11 05 6f 19 00 00 0a dc 1b 28 1a 00 00 0a 72 68 01 00 70 28 1b 00 00 0a 17 73 16 00 00 0a 13 06 1b 28 1a 00 00 0a 72 68 01 00 70 28 1b 00 00 0a 18 28 17 00 00 0a } //2
		$a_01_1 = {6b 65 79 6c 6f 67 67 65 72 2e 65 78 65 } //1 keylogger.exe
		$a_00_2 = {70 00 65 00 72 00 73 00 69 00 73 00 74 00 65 00 6e 00 63 00 65 00 5f 00 74 00 72 00 75 00 65 00 } //1 persistence_true
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1) >=4
 
}
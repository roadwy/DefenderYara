
rule Trojan_BAT_Keylogger_AR_MTB{
	meta:
		description = "Trojan:BAT/Keylogger.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 06 00 00 "
		
	strings :
		$a_02_0 = {70 0c 1f 0a 0d 72 ?? ?? ?? 70 13 04 16 13 05 2b 30 00 06 07 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 13 06 11 04 07 11 06 28 ?? ?? ?? 2b 13 07 12 07 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 13 04 00 11 05 17 58 13 05 11 05 09 fe 04 13 08 11 08 2d c5 } //10
		$a_80_1 = {21 40 23 24 25 5e 26 28 29 5b 5d 7b 7d } //!@#$%^&()[]{}  5
		$a_80_2 = {4b 45 59 4c 4f 47 47 45 52 } //KEYLOGGER  5
		$a_80_3 = {55 70 6c 6f 61 64 46 69 6c 65 } //UploadFile  4
		$a_80_4 = {2f 55 50 4c 4f 41 44 45 4e 43 2e 70 68 70 2f } ///UPLOADENC.php/  4
		$a_80_5 = {50 4f 53 54 } //POST  4
	condition:
		((#a_02_0  & 1)*10+(#a_80_1  & 1)*5+(#a_80_2  & 1)*5+(#a_80_3  & 1)*4+(#a_80_4  & 1)*4+(#a_80_5  & 1)*4) >=24
 
}
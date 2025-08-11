
rule Trojan_BAT_MassLogger_AML_MTB{
	meta:
		description = "Trojan:BAT/MassLogger.AML!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 13 40 2b 23 00 03 11 3f 11 40 91 6f ?? ?? ?? 0a 00 11 14 1d 17 9c 11 0c 11 3f 11 40 91 58 13 0c 00 11 40 17 58 13 40 11 40 11 32 fe 04 13 41 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_MassLogger_AML_MTB_2{
	meta:
		description = "Trojan:BAT/MassLogger.AML!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 0b 2b 2d 02 06 07 28 ?? 00 00 06 0c 04 03 6f ?? 00 00 0a 59 0d 03 08 09 28 ?? 00 00 06 03 08 09 28 ?? 00 00 06 03 04 28 ?? 00 00 06 07 17 58 0b 07 02 6f } //2
		$a_01_1 = {54 00 69 00 63 00 54 00 61 00 63 00 54 00 6f 00 65 00 57 00 69 00 6e 00 46 00 6f 00 72 00 6d 00 73 00 } //1 TicTacToeWinForms
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}
rule Trojan_BAT_MassLogger_AML_MTB_3{
	meta:
		description = "Trojan:BAT/MassLogger.AML!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 13 07 38 3b 01 00 00 00 02 11 05 11 07 6f ?? 00 00 0a 13 08 04 03 6f ?? 00 00 0a 59 13 09 07 72 fa 03 00 70 28 ?? 00 00 0a 2c 08 11 09 1f 64 fe 02 2b 01 16 13 0a 11 0a 2c 0d 00 11 09 1f 64 28 ?? 00 00 0a 13 09 00 11 09 19 fe 04 16 fe 01 13 0b 11 0b 2c 70 } //2
		$a_01_1 = {56 00 65 00 63 00 74 00 6f 00 72 00 5f 00 49 00 6e 00 74 00 65 00 72 00 6e 00 61 00 74 00 69 00 6f 00 6e 00 61 00 6c 00 } //1 Vector_International
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}
rule Trojan_BAT_MassLogger_AML_MTB_4{
	meta:
		description = "Trojan:BAT/MassLogger.AML!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {46 72 6f 67 67 53 65 63 75 72 69 74 79 43 68 65 63 6b 65 72 2e 46 72 6f 67 67 41 62 6f 75 74 2e 72 65 73 6f 75 72 63 65 73 } //1 FroggSecurityChecker.FroggAbout.resources
		$a_01_1 = {31 33 66 33 38 65 61 61 2d 34 34 37 65 2d 34 30 35 39 2d 38 64 62 62 2d 61 62 32 31 35 64 36 61 30 65 61 61 } //1 13f38eaa-447e-4059-8dbb-ab215d6a0eaa
		$a_01_2 = {70 00 6f 00 77 00 65 00 72 00 65 00 64 00 20 00 62 00 79 00 20 00 61 00 64 00 6d 00 69 00 6e 00 40 00 66 00 72 00 6f 00 67 00 67 00 2e 00 66 00 72 00 } //2 powered by admin@frogg.fr
		$a_01_3 = {46 00 72 00 6f 00 67 00 67 00 20 00 53 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 20 00 43 00 68 00 65 00 63 00 6b 00 65 00 72 00 } //2 Frogg Security Checker
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=6
 
}
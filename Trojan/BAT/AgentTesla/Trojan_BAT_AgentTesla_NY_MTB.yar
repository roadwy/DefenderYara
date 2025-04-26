
rule Trojan_BAT_AgentTesla_NY_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {02 03 04 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 0a 2b 00 06 2a } //1
		$a_01_1 = {18 58 19 59 fe 01 13 06 11 06 2c 04 16 0d 2b 04 09 17 58 0d 00 11 04 17 58 13 04 11 04 02 8e 69 17 59 fe 02 16 fe 01 13 07 11 07 2d b8 } //1
		$a_01_2 = {02 11 04 91 07 61 06 09 91 61 13 05 08 11 04 11 05 d2 9c 09 03 6f } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule Trojan_BAT_AgentTesla_NY_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {44 61 74 61 62 61 73 65 20 3d 20 61 6d 61 79 61 68 6f 74 65 6c 5f 64 62 3b 20 54 72 75 73 74 65 64 5f 43 6f 6e 6e 65 63 74 69 6f 6e 20 3d 20 59 65 73 } //1 Database = amayahotel_db; Trusted_Connection = Yes
		$a_81_1 = {41 6d 61 79 61 48 6f 74 65 6c 2e 52 65 73 6f 75 72 63 65 73 } //1 AmayaHotel.Resources
		$a_00_2 = {41 00 73 00 73 00 32 00 } //1 Ass2
		$a_81_3 = {41 6d 61 79 61 53 70 6c 61 73 68 53 63 72 65 65 6e } //1 AmayaSplashScreen
		$a_81_4 = {47 65 74 43 6f 6d 6d 61 6e 64 4c 69 6e 65 41 72 67 73 } //1 GetCommandLineArgs
		$a_81_5 = {50 61 73 73 77 6f 72 64 54 65 78 74 42 6f 78 } //1 PasswordTextBox
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_00_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}
rule Trojan_BAT_AgentTesla_NY_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.NY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {54 00 56 00 71 00 51 00 28 00 29 00 28 00 29 00 4d 00 28 00 29 00 28 00 29 00 28 00 29 00 28 00 29 00 45 00 28 00 29 00 28 } //1
		$a_01_1 = {50 00 67 00 49 00 44 00 4b 00 43 00 73 00 28 00 29 00 28 00 29 00 28 00 29 00 59 00 71 00 30 00 28 00 29 00 49 00 28 00 29 } //1
		$a_01_2 = {56 00 30 00 52 00 58 00 68 00 30 00 5a 00 57 00 35 00 7a 00 61 00 57 00 39 00 75 00 28 00 29 00 45 00 6c 00 44 00 62 00 32 } //1
		$a_01_3 = {28 00 29 00 28 00 29 00 4c 00 67 00 28 00 29 00 77 00 28 00 29 00 43 00 34 00 28 00 29 00 4d 00 28 00 29 00 28 00 29 00 75 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
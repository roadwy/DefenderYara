
rule Trojan_BAT_Growtopia_ADF_MTB{
	meta:
		description = "Trojan:BAT/Growtopia.ADF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,17 00 0f 00 07 00 00 "
		
	strings :
		$a_02_0 = {0a 0d 06 72 90 01 03 70 72 90 01 03 70 6f 90 01 03 0a 13 04 09 11 04 11 04 72 90 01 03 70 6f 90 01 03 0a 72 90 01 03 70 6f 90 01 03 0a 58 6f 90 01 03 0a 17 8d 90 01 03 01 13 06 11 06 16 1f 20 9d 11 06 6f 90 01 03 0a 19 9a 7e 90 01 03 0a 6f 90 01 03 0a 25 2d 06 26 72 90 01 03 70 13 05 de 0a 90 00 } //10
		$a_80_1 = {53 6f 66 74 77 61 72 65 5c 47 72 6f 77 74 6f 70 69 61 } //Software\Growtopia  5
		$a_80_2 = {74 61 6e 6b 69 64 5f 70 61 73 73 77 6f 72 64 } //tankid_password  5
		$a_80_3 = {5c 70 61 73 73 2e 74 78 74 } //\pass.txt  4
		$a_80_4 = {73 65 6c 65 63 74 20 2a 20 66 72 6f 6d 20 57 69 6e 33 32 5f 4f 70 65 72 61 74 69 6e 67 53 79 73 74 65 6d } //select * from Win32_OperatingSystem  4
		$a_80_5 = {69 70 76 34 62 6f 74 } //ipv4bot  4
		$a_80_6 = {64 69 73 63 6f 72 64 61 70 70 } //discordapp  3
	condition:
		((#a_02_0  & 1)*10+(#a_80_1  & 1)*5+(#a_80_2  & 1)*5+(#a_80_3  & 1)*4+(#a_80_4  & 1)*4+(#a_80_5  & 1)*4+(#a_80_6  & 1)*3) >=15
 
}
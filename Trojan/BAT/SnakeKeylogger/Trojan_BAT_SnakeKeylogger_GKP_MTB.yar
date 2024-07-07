
rule Trojan_BAT_SnakeKeylogger_GKP_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.GKP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {63 61 33 31 62 61 39 31 2d 36 65 30 65 2d 34 63 66 37 2d 61 38 65 30 2d 36 31 39 32 66 35 38 36 38 65 65 35 } //1 ca31ba91-6e0e-4cf7-a8e0-6192f5868ee5
		$a_81_1 = {44 41 43 6c 73 2e 65 78 65 } //1 DACls.exe
		$a_81_2 = {73 65 74 5f 55 73 65 53 79 73 74 65 6d 50 61 73 73 77 6f 72 64 43 68 61 72 } //1 set_UseSystemPasswordChar
		$a_81_3 = {51 75 61 6e 4c 79 44 61 6e 67 4b 79 49 6e 74 65 72 6e 65 74 43 6f 6e 6e 65 63 74 69 6f 6e 53 74 72 69 6e 67 } //1 QuanLyDangKyInternetConnectionString
		$a_81_4 = {43 72 65 61 74 65 44 65 6c 65 67 61 74 65 } //1 CreateDelegate
		$a_81_5 = {44 41 43 6c 73 2e 70 64 62 } //1 DACls.pdb
		$a_81_6 = {44 41 43 6c 73 2e 67 2e 72 65 73 6f 75 72 63 65 73 } //1 DACls.g.resources
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}
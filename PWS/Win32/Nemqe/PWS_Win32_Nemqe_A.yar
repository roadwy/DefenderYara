
rule PWS_Win32_Nemqe_A{
	meta:
		description = "PWS:Win32/Nemqe.A,SIGNATURE_TYPE_PEHSTR_EXT,29 00 29 00 06 00 00 "
		
	strings :
		$a_00_0 = {55 73 65 72 53 65 74 74 69 6e 67 2e 69 6e 69 } //10 UserSetting.ini
		$a_00_1 = {51 71 41 63 63 6f 75 6e 74 2e 64 6c 6c } //10 QqAccount.dll
		$a_00_2 = {54 65 6e 51 51 41 63 63 6f 75 6e 74 2e 64 6c 6c } //10 TenQQAccount.dll
		$a_02_3 = {6a 64 ff d7 eb e4 68 90 01 02 00 10 68 90 01 02 00 10 68 e8 00 00 00 68 9f 05 07 00 e8 90 01 02 00 00 68 90 01 02 00 10 68 90 01 02 00 10 68 e8 00 00 00 68 b7 2f 00 00 e8 90 01 02 00 00 90 00 } //10
		$a_00_4 = {48 61 74 61 6e 65 6d 2e 64 61 74 } //1 Hatanem.dat
		$a_00_5 = {73 75 73 65 72 3d 25 73 26 73 70 61 73 73 3d 25 73 26 73 65 72 69 61 6c 3d 25 73 26 73 65 72 4e 75 6d 3d 25 73 26 6c 65 76 65 6c 3d 25 64 26 6d 6f 6e 65 79 3d 25 64 26 6c 69 6e 65 3d 25 73 26 66 6c 61 67 3d 25 73 } //1 suser=%s&spass=%s&serial=%s&serNum=%s&level=%d&money=%d&line=%s&flag=%s
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_02_3  & 1)*10+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=41
 
}

rule PWS_Win32_QQpass_BC{
	meta:
		description = "PWS:Win32/QQpass.BC,SIGNATURE_TYPE_PEHSTR_EXT,29 00 29 00 05 00 00 "
		
	strings :
		$a_03_0 = {8a c2 8b fe 2c 90 01 01 83 c9 ff d0 e0 00 04 32 33 c0 42 f2 ae f7 d1 49 3b d1 72 e6 90 00 } //10
		$a_00_1 = {00 51 51 2e 65 78 65 00 } //10 儀⹑硥e
		$a_00_2 = {5c 44 6f 63 75 6d 65 6e 74 73 20 61 6e 64 20 53 65 74 74 69 6e 67 73 5c 41 64 6d 69 6e 69 73 74 72 61 74 6f 72 5c 41 70 70 6c 69 63 61 74 69 6f 6e 20 44 61 74 61 5c 51 51 } //10 \Documents and Settings\Administrator\Application Data\QQ
		$a_00_3 = {53 61 66 65 42 61 73 65 5c } //10 SafeBase\
		$a_00_4 = {45 6e 75 6d 50 72 6f 63 65 73 73 4d 6f 64 75 6c 65 73 } //1 EnumProcessModules
	condition:
		((#a_03_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10+(#a_00_4  & 1)*1) >=41
 
}
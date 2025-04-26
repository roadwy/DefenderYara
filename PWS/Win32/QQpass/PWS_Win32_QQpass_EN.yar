
rule PWS_Win32_QQpass_EN{
	meta:
		description = "PWS:Win32/QQpass.EN,SIGNATURE_TYPE_PEHSTR,07 00 06 00 07 00 00 "
		
	strings :
		$a_01_0 = {77 65 62 30 36 32 32 31 35 35 2e 77 32 30 31 2e 64 6e 73 35 35 38 2e 63 6f 6d 2f 30 35 2f 31 32 77 2f 71 71 32 31 2e 61 73 70 } //2 web0622155.w201.dns558.com/05/12w/qq21.asp
		$a_01_1 = {26 51 51 50 61 73 73 57 6f 72 64 3d } //1 &QQPassWord=
		$a_01_2 = {54 58 47 75 69 46 6f 75 6e 64 61 74 69 6f 6e } //1 TXGuiFoundation
		$a_01_3 = {3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 46 6f 78 69 74 20 52 65 61 64 65 72 5c 73 76 63 68 6f 73 6c 2e 65 78 65 } //1 :\Program Files\Foxit Reader\svchosl.exe
		$a_01_4 = {43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 55 73 65 72 20 53 68 65 6c 6c 20 46 6f 6c 64 65 72 73 5c 50 65 72 73 6f 6e 61 6c } //1 CurrentVersion\Explorer\User Shell Folders\Personal
		$a_01_5 = {54 45 4e 43 45 4e 54 5c 50 4c 41 54 46 4f 52 4d 5f 54 59 50 45 5f 4c 49 53 54 5c } //1 TENCENT\PLATFORM_TYPE_LIST\
		$a_01_6 = {5c 54 65 6e 63 65 6e 74 20 46 69 6c 65 73 5c 41 6c 6c 20 55 73 65 72 73 20 5c 55 73 65 72 73 } //1 \Tencent Files\All Users \Users
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=6
 
}
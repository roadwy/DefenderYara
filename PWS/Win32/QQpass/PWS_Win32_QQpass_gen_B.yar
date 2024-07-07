
rule PWS_Win32_QQpass_gen_B{
	meta:
		description = "PWS:Win32/QQpass.gen!B,SIGNATURE_TYPE_PEHSTR,0e 00 0e 00 05 00 00 "
		
	strings :
		$a_01_0 = {64 65 6c 73 65 6c 66 2e 62 61 74 } //1 delself.bat
		$a_01_1 = {32 35 45 31 45 45 43 42 2d 45 35 38 30 2d 34 30 33 32 2d 39 37 41 32 2d 41 34 35 36 44 33 33 38 32 30 44 31 } //1 25E1EECB-E580-4032-97A2-A456D33820D1
		$a_01_2 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //1 SOFTWARE\Borland\Delphi\RTL
		$a_01_3 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 53 68 65 6c 6c 45 78 65 63 75 74 65 48 6f 6f 6b 73 } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks
		$a_01_4 = {66 bf 01 00 0f b7 c7 8b 55 fc 0f b6 44 02 ff 66 89 45 fa 8d 45 f4 66 8b 55 fa 66 83 f2 0c e8 aa ee ff ff 8b 55 f4 8b c6 e8 00 ef ff ff 47 66 ff cb 75 d1 } //10
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*10) >=14
 
}
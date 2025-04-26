
rule PWS_Win32_QQpass_AA{
	meta:
		description = "PWS:Win32/QQpass.AA,SIGNATURE_TYPE_PEHSTR,14 00 14 00 0b 00 00 "
		
	strings :
		$a_01_0 = {46 3a 5c 6d 63 6b 5c 4b 6f 6c 2e 70 61 73 } //10 F:\mck\Kol.pas
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 45 78 70 6c 6f 72 65 72 5c 72 75 6e } //2 Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\run
		$a_01_2 = {51 51 3a 2d 28 } //2 QQ:-(
		$a_01_3 = {53 4f 46 54 57 41 52 45 5c 54 65 6e 63 65 6e 74 5c 51 51 } //2 SOFTWARE\Tencent\QQ
		$a_01_4 = {63 3a 5c 74 6d 70 71 71 31 30 30 30 30 2e 74 6d 70 } //2 c:\tmpqq10000.tmp
		$a_01_5 = {4b 52 65 67 45 78 2e 65 78 65 } //1 KRegEx.exe
		$a_01_6 = {4b 56 58 50 2e 6b 78 70 } //1 KVXP.kxp
		$a_01_7 = {33 36 30 74 72 61 79 2e 65 78 65 } //1 360tray.exe
		$a_01_8 = {52 53 54 72 61 79 2e 65 78 65 } //1 RSTray.exe
		$a_01_9 = {51 51 44 6f 63 74 6f 72 2e 65 78 65 } //1 QQDoctor.exe
		$a_01_10 = {44 72 52 74 70 2e 65 78 65 } //1 DrRtp.exe
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=20
 
}
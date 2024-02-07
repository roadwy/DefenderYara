
rule PWS_Win32_QQpass_CJO{
	meta:
		description = "PWS:Win32/QQpass.CJO,SIGNATURE_TYPE_PEHSTR,07 00 07 00 07 00 00 02 00 "
		
	strings :
		$a_01_0 = {00 00 74 6f 70 36 34 35 40 31 36 33 2e 63 6f 6d 00 00 43 6f 6d 62 6f 42 6f 78 00 00 00 00 ff ff ff ff 04 00 00 00 6e 75 6d 3d 00 00 00 00 ff ff ff ff 06 00 00 00 26 70 61 73 73 3d 00 00 ff ff ff ff 08 00 00 00 53 65 6e 64 20 4f 4b 21 00 } //01 00 
		$a_01_1 = {6a 75 6d 70 2e 71 71 2e 63 6f 6d 2f 63 6c 69 65 6e 74 75 72 6c } //01 00  jump.qq.com/clienturl
		$a_01_2 = {73 6d 74 70 2e 73 69 6e 61 2e 63 6f 6d 2e 63 6e } //01 00  smtp.sina.com.cn
		$a_01_3 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //01 00  SOFTWARE\Borland\Delphi\RTL
		$a_01_4 = {4d 41 49 4c 20 46 52 4f 4d 3a 3c } //01 00  MAIL FROM:<
		$a_01_5 = {49 6e 74 65 72 6e 65 74 43 6f 6e 6e 65 63 74 41 } //01 00  InternetConnectA
		$a_01_6 = {51 51 48 65 6c 70 65 72 44 6c 6c } //00 00  QQHelperDll
	condition:
		any of ($a_*)
 
}
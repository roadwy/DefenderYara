
rule PWS_Win32_QQpass_EY{
	meta:
		description = "PWS:Win32/QQpass.EY,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 69 6d 20 51 51 2e 65 78 65 } //01 00  taskkill /f /im QQ.exe
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 43 6c 61 73 73 65 73 5c 54 65 6e 63 65 6e 74 5c 55 52 4c 20 50 72 6f 74 6f 63 6f 6c } //01 00  Software\Classes\Tencent\URL Protocol
		$a_01_2 = {26 71 71 70 61 73 73 77 6f 72 64 3d 00 3f 71 71 6e 75 6d 62 65 72 3d } //01 00 
		$a_01_3 = {71 71 2f 6b 31 30 32 74 72 2f 6d 61 69 6c 2e 61 73 70 } //00 00  qq/k102tr/mail.asp
	condition:
		any of ($a_*)
 
}
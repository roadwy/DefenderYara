
rule PWS_Win32_QQpass_DR{
	meta:
		description = "PWS:Win32/QQpass.DR,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 54 65 6e 63 65 6e 74 5c 51 20 51 5c 51 51 2e 65 78 65 } //01 00  \Program Files\Tencent\Q Q\QQ.exe
		$a_01_1 = {68 74 74 70 3a 2f 2f 77 77 77 2e 69 70 31 33 38 2e 63 6f 6d 2f 69 70 73 2e 61 73 70 } //01 00  http://www.ip138.com/ips.asp
		$a_01_2 = {5c 51 51 56 53 45 54 2e 49 4e 49 } //01 00  \QQVSET.INI
		$a_01_3 = {68 74 74 70 73 3a 2f 2f 61 63 63 6f 75 6e 74 2e 71 71 2e 63 6f 6d } //01 00  https://account.qq.com
		$a_01_4 = {5c 4b 4d 65 2e 62 61 74 } //00 00  \KMe.bat
	condition:
		any of ($a_*)
 
}
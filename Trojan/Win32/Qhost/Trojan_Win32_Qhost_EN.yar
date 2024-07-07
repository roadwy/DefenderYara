
rule Trojan_Win32_Qhost_EN{
	meta:
		description = "Trojan:Win32/Qhost.EN,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 22 20 2f 76 20 22 76 2e 65 78 65 22 20 2f 74 20 52 45 47 5f 53 5a 20 2f 64 } //1 Windows\CurrentVersion\Run" /v "v.exe" /t REG_SZ /d
		$a_01_1 = {65 63 68 6f 20 31 37 38 2e 36 33 2e 39 2e 31 32 34 20 66 61 63 65 62 6f 6f 6b 2e 63 6f 6d 20 3e 3e 20 25 73 79 73 74 65 6d 72 6f 6f 74 25 5c 73 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 73 } //1 echo 178.63.9.124 facebook.com >> %systemroot%\system32\drivers\etc\hosts
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
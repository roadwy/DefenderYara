
rule Trojan_Win32_QHosts_AD{
	meta:
		description = "Trojan:Win32/QHosts.AD,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {65 63 68 6f 20 31 38 34 2e 38 32 2e 31 31 38 2e 34 37 20 20 68 74 74 70 3a 2f 2f 73 61 6e 74 61 6e 64 65 72 2e 63 6c 20 3e 3e 20 25 77 69 6e 64 69 72 25 5c 73 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 73 } //1 echo 184.82.118.47  http://santander.cl >> %windir%\system32\drivers\etc\hosts
		$a_01_1 = {73 74 61 72 74 20 68 74 74 70 3a 2f 2f 77 77 77 2e 67 75 73 61 6e 69 74 6f 2e 63 6f 6d 2f } //1 start http://www.gusanito.com/
		$a_01_2 = {65 78 69 74 70 6f 73 74 61 6c 5f 67 75 73 61 6e 69 74 6f 2e 62 61 74 } //1 exitpostal_gusanito.bat
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
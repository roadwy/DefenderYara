
rule Spyware_Win32_Look2Me_E{
	meta:
		description = "Spyware:Win32/Look2Me.E,SIGNATURE_TYPE_PEHSTR,10 00 10 00 07 00 00 "
		
	strings :
		$a_01_0 = {43 4c 53 49 44 5c 25 73 5c 49 6e 70 72 6f 63 53 65 72 76 65 72 33 32 } //5 CLSID\%s\InprocServer32
		$a_01_1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 6c 6f 67 6f 6e 5c 4e 6f 74 69 66 79 5c 47 75 61 72 64 69 61 6e } //5 SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify\Guardian
		$a_01_2 = {41 70 70 6c 69 63 61 74 69 6f 6e 20 49 6e 73 74 61 6c 6c } //5 Application Install
		$a_01_3 = {7b 44 44 46 46 41 37 35 41 } //5 {DDFFA75A
		$a_01_4 = {5a 00 45 00 52 00 4f 00 54 00 52 00 41 00 43 00 45 00 } //1 ZEROTRACE
		$a_01_5 = {53 00 55 00 52 00 46 00 53 00 43 00 41 00 4e 00 2e 00 63 00 6f 00 6d 00 } //1 SURFSCAN.com
		$a_01_6 = {63 3a 5c 4c 32 4d 20 61 70 70 6c 69 63 61 74 69 6f 6e 5c 44 65 76 5c 49 6e 73 74 61 6c 6c 65 72 } //1 c:\L2M application\Dev\Installer
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*5+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=16
 
}
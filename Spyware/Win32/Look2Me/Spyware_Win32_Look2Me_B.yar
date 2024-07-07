
rule Spyware_Win32_Look2Me_B{
	meta:
		description = "Spyware:Win32/Look2Me.B,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {5a 45 52 4f 54 52 41 43 45 20 49 6e 73 74 61 6c 6c 65 72 } //1 ZEROTRACE Installer
		$a_00_1 = {68 74 74 70 3a 2f 2f 77 77 77 2e 6c 6f 6f 6b 32 6d 65 2e 63 6f 6d 2f 63 67 69 } //1 http://www.look2me.com/cgi
		$a_00_2 = {6d 65 74 68 6f 64 3d 50 4f 53 54 } //1 method=POST
		$a_00_3 = {53 6f 66 74 77 61 72 65 5c 4c 6f 6f 6b 32 4d 65 } //1 Software\Look2Me
		$a_00_4 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //1 CreateToolhelp32Snapshot
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}
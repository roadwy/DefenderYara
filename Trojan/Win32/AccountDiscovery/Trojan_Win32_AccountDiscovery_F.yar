
rule Trojan_Win32_AccountDiscovery_F{
	meta:
		description = "Trojan:Win32/AccountDiscovery.F,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 } //1 powershell.exe
		$a_00_1 = {67 00 65 00 74 00 2d 00 6c 00 6f 00 63 00 61 00 6c 00 75 00 73 00 65 00 72 00 } //2 get-localuser
		$a_00_2 = {67 00 65 00 74 00 2d 00 6c 00 6f 00 63 00 61 00 6c 00 67 00 72 00 6f 00 75 00 70 00 } //2 get-localgroup
		$a_00_3 = {67 00 65 00 74 00 2d 00 6c 00 6f 00 63 00 61 00 6c 00 67 00 72 00 6f 00 75 00 70 00 6d 00 65 00 6d 00 62 00 65 00 72 00 } //2 get-localgroupmember
		$a_00_4 = {67 00 65 00 74 00 2d 00 67 00 70 00 6f 00 72 00 65 00 70 00 6f 00 72 00 74 00 } //2 get-gporeport
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2+(#a_00_4  & 1)*2) >=3
 
}
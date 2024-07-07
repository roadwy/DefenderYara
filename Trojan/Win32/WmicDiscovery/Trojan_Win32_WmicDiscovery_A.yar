
rule Trojan_Win32_WmicDiscovery_A{
	meta:
		description = "Trojan:Win32/WmicDiscovery.A,SIGNATURE_TYPE_CMDHSTR_EXT,32 00 32 00 05 00 00 "
		
	strings :
		$a_00_0 = {57 00 4d 00 49 00 43 00 2e 00 65 00 78 00 65 00 } //10 WMIC.exe
		$a_00_1 = {50 00 52 00 4f 00 43 00 45 00 53 00 53 00 20 00 77 00 68 00 65 00 72 00 65 00 } //10 PROCESS where
		$a_00_2 = {4e 00 61 00 6d 00 65 00 } //10 Name
		$a_00_3 = {6c 00 73 00 61 00 73 00 73 00 2e 00 65 00 78 00 65 00 } //10 lsass.exe
		$a_00_4 = {67 00 65 00 74 00 20 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 49 00 44 00 } //10 get ProcessID
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10+(#a_00_4  & 1)*10) >=50
 
}

rule Trojan_Win32_WmicDiscovery_D{
	meta:
		description = "Trojan:Win32/WmicDiscovery.D,SIGNATURE_TYPE_CMDHSTR_EXT,64 00 15 00 04 00 00 0a 00 "
		
	strings :
		$a_00_0 = {57 00 4d 00 49 00 43 00 2e 00 65 00 78 00 65 00 } //0a 00  WMIC.exe
		$a_00_1 = {64 00 61 00 74 00 61 00 66 00 69 00 6c 00 65 00 } //01 00  datafile
		$a_00_2 = {5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 63 00 6f 00 6e 00 66 00 69 00 67 00 5c 00 53 00 41 00 4d 00 } //01 00  \windows\system32\config\SAM
		$a_00_3 = {5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 63 00 6f 00 6e 00 66 00 69 00 67 00 5c 00 53 00 45 00 43 00 55 00 52 00 49 00 54 00 59 00 } //00 00  \windows\system32\config\SECURITY
	condition:
		any of ($a_*)
 
}
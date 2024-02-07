
rule PWS_Win32_Tibia_U{
	meta:
		description = "PWS:Win32/Tibia.U,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_02_0 = {68 74 74 70 3a 2f 2f 90 02 30 2f 76 69 70 2f 64 6f 64 61 6a 2e 70 68 70 3f 90 00 } //01 00 
		$a_00_1 = {53 6f 66 74 77 61 72 65 5c 5c 4d 69 63 72 6f 73 6f 66 74 5c 5c 57 69 6e 64 6f 77 73 5c 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 5c 52 75 6e 5c 5c } //01 00  Software\\Microsoft\\Windows\\CurrentVersion\\Run\\
		$a_00_2 = {25 73 5c 5c 73 79 73 74 65 6d 33 32 5c 5c 64 72 69 76 65 72 73 5c 5c 65 74 63 5c 5c 68 6f 73 74 73 } //01 00  %s\\system32\\drivers\\etc\\hosts
		$a_02_3 = {31 32 37 2e 30 2e 30 2e 31 90 02 10 6c 6f 63 61 6c 68 6f 73 74 90 00 } //01 00 
		$a_00_4 = {25 73 5c 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 5c } //01 00  %s\\Internet Explorer\\
		$a_00_5 = {54 69 62 69 61 43 6c 69 65 6e 74 } //01 00  TibiaClient
		$a_00_6 = {6c 73 61 73 73 2e 65 78 65 } //00 00  lsass.exe
	condition:
		any of ($a_*)
 
}
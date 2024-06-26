
rule Trojan_Win32_Catchman_dha{
	meta:
		description = "Trojan:Win32/Catchman!dha,SIGNATURE_TYPE_PEHSTR_EXT,05 00 03 00 09 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 74 75 64 79 20 74 68 65 20 6e 65 74 20 61 64 61 70 74 65 72 73 20 74 6f 20 77 68 69 63 68 20 74 68 65 20 63 6f 6d 70 75 74 65 72 20 68 61 73 20 63 6f 6e 6e 65 63 74 65 64 } //01 00  Study the net adapters to which the computer has connected
		$a_01_1 = {5c 73 79 73 74 65 6d 33 32 5c 77 62 65 6d 5c 74 6d 66 5c } //01 00  \system32\wbem\tmf\
		$a_01_2 = {5c 57 69 6e 64 6f 77 73 5c 43 61 63 68 65 73 5c 63 61 63 68 65 73 5f 76 65 72 73 69 6f 6e 2e 64 62 } //01 00  \Windows\Caches\caches_version.db
		$a_01_3 = {74 68 65 20 63 6c 69 70 20 66 69 6c 65 6e 61 6d 65 20 69 73 3a } //01 00  the clip filename is:
		$a_01_4 = {5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 42 75 72 6e 5c } //01 00  \Microsoft\Windows\Burn\
		$a_01_5 = {52 69 67 68 74 20 4d 45 4e 55 20 6b 65 79 } //01 00  Right MENU key
		$a_01_6 = {43 6f 6e 74 72 6f 6c 2d 62 72 65 61 6b 20 70 72 6f 63 65 73 73 69 6e 67 } //01 00  Control-break processing
		$a_01_7 = {61 63 74 69 76 69 6e 67 } //01 00  activing
		$a_01_8 = {67 6f 69 6e 67 20 61 68 65 61 64 20 6f 66 20 77 68 61 74 77 68 65 72 65 } //00 00  going ahead of whatwhere
	condition:
		any of ($a_*)
 
}

rule Trojan_WinNT_Sirefef_J{
	meta:
		description = "Trojan:WinNT/Sirefef.J,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {5c 00 64 00 72 00 69 00 76 00 65 00 72 00 5c 00 25 00 49 00 36 00 34 00 75 00 } //01 00  \driver\%I64u
		$a_00_1 = {5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 72 00 6f 00 6f 00 74 00 5c 00 24 00 4e 00 74 00 55 00 6e 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 4b 00 42 00 25 00 75 00 24 00 } //01 00  \systemroot\$NtUninstallKB%u$
		$a_03_2 = {8b 54 24 2c 8b 4c 24 30 8b 44 24 3c 89 56 0c 8b 54 24 34 89 4e 14 89 46 10 89 56 2c a1 90 01 04 8b 40 14 8b 50 2c 89 51 2c 8b 50 30 8b 7c 24 30 89 57 30 8b 50 24 89 51 24 8b 40 28 89 41 28 8b 4c 24 44 51 56 ff 54 24 3c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_WinNT_Sirefef_J_2{
	meta:
		description = "Trojan:WinNT/Sirefef.J,SIGNATURE_TYPE_ARHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {5c 00 64 00 72 00 69 00 76 00 65 00 72 00 5c 00 25 00 49 00 36 00 34 00 75 00 } //01 00  \driver\%I64u
		$a_00_1 = {5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 72 00 6f 00 6f 00 74 00 5c 00 24 00 4e 00 74 00 55 00 6e 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 4b 00 42 00 25 00 75 00 24 00 } //01 00  \systemroot\$NtUninstallKB%u$
		$a_03_2 = {8b 54 24 2c 8b 4c 24 30 8b 44 24 3c 89 56 0c 8b 54 24 34 89 4e 14 89 46 10 89 56 2c a1 90 01 04 8b 40 14 8b 50 2c 89 51 2c 8b 50 30 8b 7c 24 30 89 57 30 8b 50 24 89 51 24 8b 40 28 89 41 28 8b 4c 24 44 51 56 ff 54 24 3c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
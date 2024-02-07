
rule Trojan_Win32_Ruce_gen_A{
	meta:
		description = "Trojan:Win32/Ruce.gen!A,SIGNATURE_TYPE_PEHSTR,38 00 37 00 07 00 00 32 00 "
		
	strings :
		$a_01_0 = {53 59 53 54 45 4d 5c 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 5c 53 65 72 76 69 63 65 73 5c 5c 53 68 61 72 65 64 41 63 63 65 73 73 5c 5c 50 61 72 61 6d 65 74 65 72 73 5c 5c 46 69 72 65 77 61 6c 6c 50 6f 6c 69 63 79 5c 5c 53 74 61 6e 64 61 72 64 50 72 6f 66 69 6c 65 5c 5c 41 75 74 68 6f 72 69 7a 65 64 41 70 70 6c 69 63 61 74 69 6f 6e 73 5c 5c 4c 69 73 74 } //32 00  SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile\\AuthorizedApplications\\List
		$a_01_1 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 53 68 61 72 65 64 41 63 63 65 73 73 5c 50 61 72 61 6d 65 74 65 72 73 5c 46 69 72 65 77 61 6c 6c 50 6f 6c 69 63 79 5c 53 74 61 6e 64 61 72 64 50 72 6f 66 69 6c 65 5c 41 75 74 68 6f 72 69 7a 65 64 41 70 70 6c 69 63 61 74 69 6f 6e 73 5c 4c 69 73 74 } //05 00  SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile\AuthorizedApplications\List
		$a_01_2 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 69 65 78 70 6c 6f 72 65 2e 65 78 65 3a 2a 3a 45 6e 61 62 6c 65 64 3a 4f 75 74 70 72 65 73 73 00 } //05 00 
		$a_01_3 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 69 65 78 70 6c 6f 72 65 2e 65 78 65 3a 2a 3a 45 6e 61 62 6c 65 64 3a 4d 69 63 72 6f 73 6f 66 74 20 4f 6e 6c 69 6e 65 20 55 70 64 61 74 65 00 } //01 00 
		$a_01_4 = {25 50 44 46 2d 31 00 00 65 78 65 00 4e 65 74 00 63 6d 64 2e 65 78 65 00 4b 69 6c 46 61 69 6c } //01 00 
		$a_01_5 = {4d 53 49 45 20 37 2e 30 3b 29 00 77 62 00 00 65 78 65 00 4e 65 74 00 } //01 00 
		$a_01_6 = {21 40 23 24 25 5e 00 00 65 78 65 00 4e 65 74 00 63 6d 64 2e 65 78 65 00 64 69 72 } //00 00 
	condition:
		any of ($a_*)
 
}
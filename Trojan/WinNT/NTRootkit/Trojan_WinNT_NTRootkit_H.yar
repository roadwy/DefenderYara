
rule Trojan_WinNT_NTRootkit_H{
	meta:
		description = "Trojan:WinNT/NTRootkit.H,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_02_0 = {53 79 73 74 65 6d 00 56 57 ff 15 90 01 04 8b f8 33 f6 6a 06 8d 04 3e 50 68 90 01 04 ff 15 90 01 04 83 c4 0c 85 c0 74 0e 46 81 fe 00 30 00 00 7c df 33 c0 5f 5e c3 90 00 } //01 00 
		$a_02_1 = {fa 8b 49 01 8b 1d 90 01 04 b8 90 01 04 8d 0c 8b 87 01 a3 90 00 } //01 00 
		$a_02_2 = {8b 4f 01 b8 90 01 04 8d 0c 8a 87 01 a3 90 01 04 fb 90 00 } //01 00 
		$a_00_3 = {5c 00 52 00 65 00 67 00 69 00 73 00 74 00 72 00 79 00 5c 00 4d 00 41 00 43 00 48 00 49 00 4e 00 45 00 5c 00 53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 } //00 00  \Registry\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
	condition:
		any of ($a_*)
 
}
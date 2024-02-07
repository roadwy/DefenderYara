
rule Worm_Win32_Gamarue_G_MSR{
	meta:
		description = "Worm:Win32/Gamarue.G!MSR,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 06 00 00 05 00 "
		
	strings :
		$a_01_0 = {53 68 65 6c 6c 45 78 65 63 5c 6f 75 74 5c 72 65 6c 65 61 73 65 5c 64 6c 6d 71 73 6a 77 79 2e 70 64 62 } //02 00  ShellExec\out\release\dlmqsjwy.pdb
		$a_01_1 = {53 4f 63 74 6e 4d 49 79 43 4b 6d 57 46 52 52 61 } //02 00  SOctnMIyCKmWFRRa
		$a_01_2 = {62 69 6d 64 62 65 78 6e 6e 76 79 68 } //02 00  bimdbexnnvyh
		$a_01_3 = {67 78 4d 51 48 43 57 41 57 53 6b } //02 00  gxMQHCWAWSk
		$a_01_4 = {79 6f 6a 64 6d 66 77 73 63 6d 72 } //02 00  yojdmfwscmr
		$a_01_5 = {7a 57 4e 6f 77 69 56 66 4b 41 51 64 53 76 } //00 00  zWNowiVfKAQdSv
		$a_00_6 = {78 9b } //00 00 
	condition:
		any of ($a_*)
 
}
rule Worm_Win32_Gamarue_G_MSR_2{
	meta:
		description = "Worm:Win32/Gamarue.G!MSR,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 06 00 00 05 00 "
		
	strings :
		$a_01_0 = {53 68 65 6c 6c 45 78 65 63 5c 6f 75 74 5c 72 65 6c 65 61 73 65 5c 76 76 70 68 70 64 69 74 2e 70 64 62 } //05 00  ShellExec\out\release\vvphpdit.pdb
		$a_01_1 = {53 68 65 6c 6c 45 78 65 63 5c 6f 75 74 5c 72 65 6c 65 61 73 65 5c 62 70 7a 77 65 72 75 2e 70 64 62 } //02 00  ShellExec\out\release\bpzweru.pdb
		$a_01_2 = {52 42 70 78 41 6e 55 44 5a 53 65 69 7a } //02 00  RBpxAnUDZSeiz
		$a_01_3 = {63 6d 66 76 64 77 7a 74 71 6f 79 74 78 } //02 00  cmfvdwztqoytx
		$a_01_4 = {62 6e 69 79 77 61 6d 6f 73 6a 6f 6a 77 62 6a 6b } //02 00  bniywamosjojwbjk
		$a_01_5 = {67 77 61 57 64 46 76 76 6f 63 51 } //00 00  gwaWdFvvocQ
		$a_00_6 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}
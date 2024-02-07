
rule Ransom_Win32_Paradise_A_MSR{
	meta:
		description = "Ransom:Win32/Paradise.A!MSR,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {59 6f 75 72 20 69 6d 70 6f 72 74 61 6e 74 20 66 69 6c 65 73 20 70 72 6f 64 75 63 65 64 20 6f 6e 20 74 68 69 73 20 63 6f 6d 70 75 74 65 72 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 20 64 75 65 20 61 20 73 65 63 75 72 69 74 79 20 70 72 6f 62 6c 65 6d } //01 00  Your important files produced on this computer have been encrypted due a security problem
		$a_01_1 = {44 6f 20 6e 6f 74 20 61 74 74 65 6d 70 74 20 74 6f 20 75 73 65 20 74 68 65 20 61 6e 74 69 76 69 72 75 73 20 6f 72 20 75 6e 69 6e 73 74 61 6c 6c 20 74 68 65 20 70 72 6f 67 72 61 6d } //01 00  Do not attempt to use the antivirus or uninstall the program
		$a_01_2 = {2d 00 2d 00 2d 00 3d 00 3d 00 25 00 24 00 24 00 24 00 4f 00 50 00 45 00 4e 00 5f 00 4d 00 45 00 5f 00 55 00 50 00 24 00 24 00 24 00 3d 00 3d 00 2d 00 2d 00 2d 00 2e 00 74 00 78 00 74 00 } //01 00  ---==%$$$OPEN_ME_UP$$$==---.txt
		$a_01_3 = {64 00 65 00 6c 00 65 00 74 00 65 00 20 00 73 00 68 00 61 00 64 00 6f 00 77 00 73 00 20 00 2f 00 61 00 6c 00 6c 00 20 00 2f 00 71 00 75 00 69 00 65 00 74 00 } //00 00  delete shadows /all /quiet
	condition:
		any of ($a_*)
 
}
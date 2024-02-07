
rule Trojan_Win32_EmotetCrypt_PCP_MTB{
	meta:
		description = "Trojan:Win32/EmotetCrypt.PCP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_81_0 = {63 3a 5c 55 73 65 72 73 5c 44 4f 44 4f 5c 56 69 64 65 6f 73 5c 54 72 61 6e 73 70 61 72 65 6e 74 43 6f 6e 74 72 6f 6c 5f 73 72 63 5c 54 72 61 6e 73 70 61 72 65 6e 74 43 6f 6e 74 72 6f 6c 5c 52 65 6c 65 61 73 65 5c 54 72 61 6e 73 70 61 72 65 6e 74 43 6f 6e 74 72 6f 6c 2e 70 64 62 } //01 00  c:\Users\DODO\Videos\TransparentControl_src\TransparentControl\Release\TransparentControl.pdb
		$a_81_1 = {43 53 42 68 76 53 57 43 76 46 52 76 66 43 66 41 6f 4a 64 6f 46 75 41 55 6d 4b } //00 00  CSBhvSWCvFRvfCfAoJdoFuAUmK
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_EmotetCrypt_PCP_MTB_2{
	meta:
		description = "Trojan:Win32/EmotetCrypt.PCP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1b 00 1b 00 09 00 00 0b 00 "
		
	strings :
		$a_81_0 = {37 4d 7a 4e 66 30 6c 45 4d 46 64 71 44 53 4e } //09 00  7MzNf0lEMFdqDSN
		$a_81_1 = {33 55 36 52 73 6a 56 66 30 73 74 30 54 4a 66 2e 70 64 62 } //07 00  3U6RsjVf0st0TJf.pdb
		$a_81_2 = {71 73 6a 77 57 49 75 54 59 64 66 76 6b 54 69 } //0b 00  qsjwWIuTYdfvkTi
		$a_81_3 = {6a 5a 54 6e 69 62 53 65 61 66 4c 47 43 48 47 54 } //09 00  jZTnibSeafLGCHGT
		$a_81_4 = {6e 74 65 72 44 72 69 76 2e 75 75 2e 70 64 62 } //07 00  nterDriv.uu.pdb
		$a_81_5 = {48 57 57 65 74 74 74 45 45 } //0b 00  HWWetttEE
		$a_81_6 = {66 54 68 44 54 64 71 59 42 48 54 2e 63 61 62 } //09 00  fThDTdqYBHT.cab
		$a_81_7 = {74 4e 63 36 4c 37 35 2a 39 2f 7a 2e 70 64 62 } //07 00  tNc6L75*9/z.pdb
		$a_81_8 = {61 35 4a 41 51 73 63 6e 41 47 } //00 00  a5JAQscnAG
	condition:
		any of ($a_*)
 
}
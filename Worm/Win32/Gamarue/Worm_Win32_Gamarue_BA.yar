
rule Worm_Win32_Gamarue_BA{
	meta:
		description = "Worm:Win32/Gamarue.BA,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 07 00 00 03 00 "
		
	strings :
		$a_01_0 = {5c 44 65 73 6b 74 6f 70 5c 53 68 65 6c 6c 45 78 65 63 5c 6f 75 74 5c } //03 00  \Desktop\ShellExec\out\
		$a_01_1 = {62 00 4b 00 52 00 73 00 7a 00 67 00 53 00 4b 00 74 00 66 00 45 00 00 00 5c 00 49 00 6e 00 64 00 65 00 78 00 65 00 72 00 56 00 6f 00 6c 00 75 00 6d 00 65 00 47 00 75 00 69 00 64 00 } //02 00 
		$a_01_2 = {6f 65 7a 71 65 6e 66 34 6d 6c 68 78 63 6d 34 76 6e 6f 35 67 6f 61 76 71 73 6b 6f 38 6d 6b 75 72 37 75 79 6e 6a 6e 69 31 6c 31 36 71 32 65 74 78 35 35 77 66 75 6d 78 6b } //02 00  oezqenf4mlhxcm4vno5goavqsko8mkur7uynjni1l16q2etx55wfumxk
		$a_01_3 = {5c 70 69 74 67 6e 70 65 74 76 67 6b 2e 70 64 62 } //01 00  \pitgnpetvgk.pdb
		$a_01_4 = {78 64 78 6b 6a 65 6e 69 61 63 65 } //01 00  xdxkjeniace
		$a_01_5 = {71 62 72 65 78 6b 73 41 4d 68 79 } //01 00  qbrexksAMhy
		$a_01_6 = {6f 62 6a 3d 25 53 3b 25 73 } //00 00  obj=%S;%s
		$a_00_7 = {5d 04 00 00 ea } //99 03 
	condition:
		any of ($a_*)
 
}

rule VirTool_Win32_VBInject_gen_AQ{
	meta:
		description = "VirTool:Win32/VBInject.gen!AQ,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {79 00 72 00 6f 00 6d 00 65 00 4d 00 73 00 73 00 65 00 63 00 6f 00 72 00 50 00 65 00 74 00 69 00 72 00 57 00 } //01 00  yromeMssecorPetirW
		$a_01_1 = {74 00 78 00 65 00 74 00 6e 00 6f 00 43 00 64 00 61 00 65 00 72 00 68 00 54 00 74 00 65 00 53 00 } //01 00  txetnoCdaerhTteS
		$a_01_2 = {6e 00 6f 00 69 00 74 00 63 00 65 00 53 00 66 00 4f 00 77 00 65 00 69 00 56 00 70 00 61 00 6d 00 6e 00 55 00 74 00 4e 00 } //01 00  noitceSfOweiVpamnUtN
		$a_01_3 = {54 00 77 00 6f 00 66 00 69 00 73 00 68 00 20 00 64 00 65 00 63 00 72 00 79 00 70 00 74 00 69 00 6f 00 6e 00 } //01 00  Twofish decryption
		$a_01_4 = {74 00 6e 00 75 00 6f 00 43 00 6b 00 63 00 69 00 54 00 74 00 65 00 47 00 } //01 00  tnuoCkciTteG
		$a_01_5 = {44 65 63 72 79 70 74 46 69 6c 65 } //02 00  DecryptFile
		$a_01_6 = {62 00 2d 00 32 00 72 00 46 00 66 00 36 00 63 00 2a 00 72 00 } //00 00  b-2rFf6c*r
	condition:
		any of ($a_*)
 
}
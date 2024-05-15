
rule HackTool_Win64_Cryptor_JZ_MTB{
	meta:
		description = "HackTool:Win64/Cryptor.JZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {65 6e 63 72 79 70 74 20 66 69 6c 65 } //01 00  encrypt file
		$a_01_1 = {64 65 63 72 79 70 74 20 66 69 6c 65 } //01 00  decrypt file
		$a_01_2 = {74 65 73 74 20 65 6e 63 72 79 70 74 69 6f 6e } //01 00  test encryption
		$a_01_3 = {6c 6f 61 64 20 65 6e 63 72 79 70 74 65 64 20 64 6c 6c } //01 00  load encrypted dll
		$a_01_4 = {6d 79 66 69 6c 65 2e 74 78 74 2e 65 6e 63 } //00 00  myfile.txt.enc
	condition:
		any of ($a_*)
 
}
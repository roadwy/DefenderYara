
rule Ransom_MSIL_HiddenTear_PF_MTB{
	meta:
		description = "Ransom:MSIL/HiddenTear.PF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 00 6c 00 6f 00 63 00 6b 00 65 00 64 00 } //01 00  .locked
		$a_01_1 = {5c 00 55 00 4e 00 4c 00 4f 00 43 00 4b 00 5f 00 46 00 49 00 4c 00 45 00 53 00 5f 00 49 00 4e 00 53 00 54 00 52 00 55 00 43 00 54 00 49 00 4f 00 4e 00 53 00 2e 00 74 00 78 00 74 00 } //01 00  \UNLOCK_FILES_INSTRUCTIONS.txt
		$a_01_2 = {2f 00 63 00 20 00 76 00 73 00 73 00 61 00 64 00 6d 00 69 00 6e 00 20 00 64 00 65 00 6c 00 65 00 74 00 65 00 20 00 73 00 68 00 61 00 64 00 6f 00 77 00 73 00 20 00 2f 00 61 00 6c 00 6c 00 20 00 2f 00 71 00 75 00 69 00 65 00 74 00 } //01 00  /c vssadmin delete shadows /all /quiet
		$a_01_3 = {41 6c 6c 20 79 6f 75 72 20 69 6d 70 6f 72 74 61 6e 74 20 66 69 6c 65 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 } //00 00  All your important files are encrypted
	condition:
		any of ($a_*)
 
}
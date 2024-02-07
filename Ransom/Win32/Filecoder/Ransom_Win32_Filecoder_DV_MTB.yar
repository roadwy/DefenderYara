
rule Ransom_Win32_Filecoder_DV_MTB{
	meta:
		description = "Ransom:Win32/Filecoder.DV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 01 00 "
		
	strings :
		$a_81_0 = {55 6e 61 62 6c 65 20 74 6f 20 70 65 72 66 6f 72 6d 20 6d 69 6c 69 74 61 72 79 20 67 72 61 64 65 20 41 45 53 32 35 36 20 65 6e 63 72 79 70 74 69 6f 6e 20 66 6f 72 20 66 69 6c 65 20 21 } //01 00  Unable to perform military grade AES256 encryption for file !
		$a_81_1 = {2e 65 6e 63 43 6f 75 6c 64 20 6e 6f 74 20 73 65 6e 64 20 70 61 63 6b 65 74 20 74 6f 20 2e } //01 00  .encCould not send packet to .
		$a_81_2 = {54 68 69 73 20 70 72 6f 67 72 61 6d 20 65 78 65 63 75 74 65 73 20 70 6f 74 65 6e 74 69 61 6c 6c 79 20 64 61 6e 67 72 65 6f 75 73 20 6f 70 65 72 61 74 69 6f 6e 73 } //01 00  This program executes potentially dangreous operations
		$a_81_3 = {57 65 27 72 65 20 67 6f 69 6e 67 20 74 6f 20 65 6e 63 72 79 70 74 20 41 4c 4c 20 54 48 45 20 54 48 49 4e 47 53 2e 20 54 79 70 65 20 27 59 45 53 27 20 74 6f 20 63 6f 6e 74 69 6e 75 65 2e } //01 00  We're going to encrypt ALL THE THINGS. Type 'YES' to continue.
		$a_81_4 = {75 75 75 75 75 75 75 75 62 74 6e 75 66 72 75 75 75 75 75 75 75 75 75 75 75 75 75 75 75 75 75 75 } //01 00  uuuuuuuubtnufruuuuuuuuuuuuuuuuuu
		$a_81_5 = {4f 6e 63 65 20 69 6e 73 74 61 6e 63 65 20 68 61 73 20 70 72 65 76 69 6f 75 73 6c 79 20 62 65 65 6e 20 70 6f 69 73 6f 6e 65 64 } //00 00  Once instance has previously been poisoned
	condition:
		any of ($a_*)
 
}
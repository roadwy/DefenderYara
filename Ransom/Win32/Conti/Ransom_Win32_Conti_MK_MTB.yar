
rule Ransom_Win32_Conti_MK_MTB{
	meta:
		description = "Ransom:Win32/Conti.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 06 00 00 05 00 "
		
	strings :
		$a_81_0 = {63 6f 6e 74 69 5f 76 33 5c 52 65 6c 65 61 73 65 5c 63 72 79 70 74 6f 72 2e 70 64 62 } //05 00  conti_v3\Release\cryptor.pdb
		$a_81_1 = {49 66 20 79 6f 75 20 74 72 79 20 74 6f 20 75 73 65 20 61 6e 79 20 61 64 64 69 74 69 6f 6e 61 6c 20 72 65 63 6f 76 65 72 79 20 73 6f 66 74 77 61 72 65 20 2d 20 74 68 65 20 66 69 6c 65 73 20 6d 69 67 68 74 20 62 65 20 64 61 6d 61 67 65 64 20 6f 72 20 6c 6f 73 74 } //05 00  If you try to use any additional recovery software - the files might be damaged or lost
		$a_81_2 = {54 6f 20 6d 61 6b 65 20 73 75 72 65 20 74 68 61 74 20 77 65 20 52 45 41 4c 4c 59 20 43 41 4e 20 72 65 63 6f 76 65 72 20 64 61 74 61 20 2d 20 77 65 20 6f 66 66 65 72 20 79 6f 75 20 74 6f 20 64 65 63 72 79 70 74 20 73 61 6d 70 6c 65 73 } //05 00  To make sure that we REALLY CAN recover data - we offer you to decrypt samples
		$a_81_3 = {63 6f 6e 74 69 72 65 63 6f 76 65 72 79 2e 69 6e 66 6f } //05 00  contirecovery.info
		$a_81_4 = {59 4f 55 20 53 48 4f 55 4c 44 20 42 45 20 41 57 41 52 45 21 } //05 00  YOU SHOULD BE AWARE!
		$a_81_5 = {57 65 27 76 65 20 64 6f 77 6e 6c 6f 61 64 65 64 20 79 6f 75 72 20 64 61 74 61 20 61 6e 64 20 61 72 65 20 72 65 61 64 79 20 74 6f 20 70 75 62 6c 69 73 68 20 69 74 20 6f 6e 20 6f 75 74 20 6e 65 77 73 20 77 65 62 73 69 74 65 20 69 66 20 79 6f 75 20 64 6f 20 6e 6f 74 20 72 65 73 70 6f 6e 64 } //00 00  We've downloaded your data and are ready to publish it on out news website if you do not respond
		$a_00_6 = {5d 04 00 00 ea 62 04 80 5c 34 00 00 ec 62 04 80 00 00 01 00 } //32 00 
	condition:
		any of ($a_*)
 
}
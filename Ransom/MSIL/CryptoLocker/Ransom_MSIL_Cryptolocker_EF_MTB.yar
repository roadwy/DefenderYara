
rule Ransom_MSIL_Cryptolocker_EF_MTB{
	meta:
		description = "Ransom:MSIL/Cryptolocker.EF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,4a 00 4a 00 08 00 00 32 00 "
		
	strings :
		$a_81_0 = {65 72 61 77 6f 73 6e 61 72 } //32 00  erawosnar
		$a_81_1 = {44 65 6c 74 61 4d 4d 4d 4d 44 43 43 58 43 49 49 49 5f 50 52 4f 43 45 53 53 } //14 00  DeltaMMMMDCCXCIII_PROCESS
		$a_81_2 = {2e 73 69 63 6b } //14 00  .sick
		$a_81_3 = {47 6f 20 63 6c 65 61 6e 20 74 68 69 73 20 73 68 69 74 20 66 61 73 74 } //03 00  Go clean this shit fast
		$a_81_4 = {55 72 46 69 6c 65 2e 54 58 54 } //03 00  UrFile.TXT
		$a_81_5 = {55 72 20 64 75 6d 62 20 61 66 20 72 65 74 61 72 64 65 64 20 30 69 71 20 6b 69 64 } //01 00  Ur dumb af retarded 0iq kid
		$a_81_6 = {59 6f 75 72 54 78 74 4d 73 67 } //01 00  YourTxtMsg
		$a_81_7 = {77 61 72 6e 69 6e 67 2e 42 61 63 6b 67 72 6f 75 6e 64 49 6d 61 67 65 } //00 00  warning.BackgroundImage
	condition:
		any of ($a_*)
 
}
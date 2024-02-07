
rule Ransom_MSIL_Conti_MA_MTB{
	meta:
		description = "Ransom:MSIL/Conti.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0c 00 00 01 00 "
		
	strings :
		$a_01_0 = {45 43 6f 6e 74 69 2c 20 48 4f 57 5f 54 4f 5f 44 45 43 52 59 50 54 50 2c 20 54 68 65 20 73 79 73 74 65 6d 20 69 73 20 4c 4f 43 4b 45 44 2e 2c 20 54 68 65 20 6e 65 74 77 6f 72 6b 20 69 73 20 4c 4f 43 4b 45 44 2e } //01 00  EConti, HOW_TO_DECRYPTP, The system is LOCKED., The network is LOCKED.
		$a_01_1 = {50 65 6e 74 65 72 57 61 72 65 } //01 00  PenterWare
		$a_01_2 = {47 65 74 46 72 65 65 53 70 61 63 65 4d 42 } //01 00  GetFreeSpaceMB
		$a_01_3 = {46 6f 72 63 65 43 6f 70 79 46 69 6c 65 } //01 00  ForceCopyFile
		$a_01_4 = {53 68 72 65 64 46 69 6c 65 } //01 00  ShredFile
		$a_01_5 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_01_6 = {45 6e 63 72 79 70 74 65 64 46 69 6c 65 73 } //01 00  EncryptedFiles
		$a_01_7 = {5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 44 00 61 00 74 00 61 00 5c 00 50 00 65 00 6e 00 74 00 65 00 72 00 57 00 61 00 72 00 65 00 2e 00 74 00 78 00 74 00 } //01 00  \ProgramData\PenterWare.txt
		$a_01_8 = {65 00 63 00 68 00 6f 00 20 00 6a 00 20 00 7c 00 20 00 64 00 65 00 6c 00 20 00 64 00 65 00 6c 00 65 00 74 00 65 00 4d 00 79 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 2e 00 62 00 61 00 74 00 } //01 00  echo j | del deleteMyProgram.bat
		$a_01_9 = {44 00 65 00 6c 00 65 00 74 00 65 00 53 00 68 00 61 00 64 00 6f 00 77 00 4d 00 6f 00 64 00 65 00 } //01 00  DeleteShadowMode
		$a_01_10 = {52 00 61 00 6e 00 73 00 6f 00 6d 00 4e 00 6f 00 74 00 65 00 2e 00 50 00 4e 00 54 00 2d 00 52 00 4e 00 53 00 4d 00 } //01 00  RansomNote.PNT-RNSM
		$a_01_11 = {76 00 73 00 73 00 61 00 64 00 6d 00 69 00 6e 00 2e 00 65 00 78 00 65 00 20 00 64 00 65 00 6c 00 65 00 74 00 65 00 20 00 73 00 68 00 61 00 64 00 6f 00 77 00 73 00 20 00 2f 00 61 00 6c 00 6c 00 20 00 2f 00 71 00 75 00 69 00 65 00 74 00 20 00 2f 00 3f 00 } //00 00  vssadmin.exe delete shadows /all /quiet /?
	condition:
		any of ($a_*)
 
}
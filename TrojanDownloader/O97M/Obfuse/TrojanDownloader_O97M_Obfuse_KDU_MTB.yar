
rule TrojanDownloader_O97M_Obfuse_KDU_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.KDU!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {67 4b 44 55 75 77 58 79 43 66 49 4e 73 56 4c 2e 6d 55 51 6e 58 64 77 52 78 4b 4c 42 41 53 4a 2e 43 6f 6e 74 72 6f 6c 54 69 70 54 65 78 74 20 3d 20 67 4b 44 55 75 77 58 79 43 66 49 4e 73 56 4c 2e 53 77 74 4d 65 62 52 42 45 73 69 6d 2e 54 61 67 } //01 00  gKDUuwXyCfINsVL.mUQnXdwRxKLBASJ.ControlTipText = gKDUuwXyCfINsVL.SwtMebRBEsim.Tag
		$a_01_1 = {67 4b 44 55 75 77 58 79 43 66 49 4e 73 56 4c 2e 48 71 4d 74 67 54 70 4c 6e 76 45 5a 6b 51 41 2e 43 6f 6e 74 72 6f 6c 54 69 70 54 65 78 74 20 3d 20 67 4b 44 55 75 77 58 79 43 66 49 4e 73 56 4c 2e 50 43 42 6f 75 4f 73 5a 56 61 59 6b 2e 54 61 67 } //01 00  gKDUuwXyCfINsVL.HqMtgTpLnvEZkQA.ControlTipText = gKDUuwXyCfINsVL.PCBouOsZVaYk.Tag
		$a_01_2 = {67 4b 44 55 75 77 58 79 43 66 49 4e 73 56 4c 2e 4a 4f 61 63 79 49 76 6e 5a 55 4d 41 2e 41 75 74 6f 53 69 7a 65 20 3d 20 54 72 75 65 } //01 00  gKDUuwXyCfINsVL.JOacyIvnZUMA.AutoSize = True
		$a_01_3 = {53 68 65 6c 6c 20 67 4b 44 55 75 77 58 79 43 66 49 4e 73 56 4c 2e 62 48 45 53 74 6b 51 57 64 6c 73 43 6d 59 70 47 50 44 63 77 4e 52 55 79 6e 2e 54 61 67 2c } //01 00  Shell gKDUuwXyCfINsVL.bHEStkQWdlsCmYpGPDcwNRUyn.Tag,
		$a_01_4 = {4d 73 67 42 6f 78 20 22 44 6f 63 75 6d 65 6e 74 20 63 61 6e 6e 6f 74 20 62 65 20 6f 70 65 6e 65 64 22 } //00 00  MsgBox "Document cannot be opened"
	condition:
		any of ($a_*)
 
}
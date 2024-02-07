
rule TrojanDownloader_O97M_Obfuse_MT_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.MT!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 72 69 76 61 74 65 20 44 65 63 6c 61 72 65 20 50 74 72 53 61 66 65 20 46 75 6e 63 74 69 6f 6e 20 53 65 74 54 69 6d 65 72 20 4c 69 62 20 22 75 73 65 72 33 32 22 20 28 42 79 56 61 6c 20 68 57 6e 64 20 41 73 20 4c 6f 6e 67 50 74 72 2c } //01 00  Private Declare PtrSafe Function SetTimer Lib "user32" (ByVal hWnd As LongPtr,
		$a_01_1 = {50 75 74 20 23 31 2c 20 2c 20 54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 44 65 66 61 75 6c 74 54 61 72 67 65 74 46 72 61 6d 65 20 26 20 22 73 2e 63 6f 6d 2f 4c 45 4f 35 47 44 4b 5a 43 50 2e 70 6e 67 27 2c } //01 00  Put #1, , ThisDocument.DefaultTargetFrame & "s.com/LEO5GDKZCP.png',
		$a_01_2 = {27 43 3a 5c 50 73 69 43 6f 6e 74 65 6e 74 5c 50 53 78 6f 65 70 31 2e 65 78 65 27 29 22 } //01 00  'C:\PsiContent\PSxoep1.exe')"
		$a_01_3 = {26 20 22 2e 62 61 74 22 } //01 00  & ".bat"
		$a_01_4 = {53 65 6c 65 63 74 69 6f 6e 2e 54 79 70 65 54 65 78 74 20 54 65 78 74 3a 3d } //00 00  Selection.TypeText Text:=
	condition:
		any of ($a_*)
 
}
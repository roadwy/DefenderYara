
rule TrojanDownloader_O97M_Trickbot_YA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Trickbot.YA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {4f 70 65 6e 20 22 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 46 45 72 69 6f 2e 76 62 73 22 20 46 6f 72 20 42 69 6e 61 72 79 } //01 00  Open "C:\ProgramData\FErio.vbs" For Binary
		$a_01_1 = {4f 70 65 6e 20 22 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 42 6c 6f 62 65 72 73 2e 76 62 73 22 20 46 6f 72 20 42 69 6e 61 72 79 20 41 73 } //01 00  Open "C:\ProgramData\Blobers.vbs" For Binary As
		$a_01_2 = {53 65 74 20 4d 61 6d 74 65 72 73 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 58 4d 4c 53 61 76 65 54 68 72 6f 75 67 68 58 53 4c 54 } //01 00  Set Mamters = CreateObject(ThisDocument.XMLSaveThroughXSLT
		$a_01_3 = {4d 61 6d 74 65 72 73 2e 45 78 65 63 } //00 00  Mamters.Exec
	condition:
		any of ($a_*)
 
}

rule TrojanDownloader_O97M_EncDoc_PT_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.PT!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 4d 69 63 72 6f 73 6f 66 74 2e 58 4d 4c 44 4f 4d 22 29 2e 43 72 65 61 74 65 45 6c 65 6d 65 6e 74 28 22 62 36 34 22 29 } //01 00  CreateObject("Microsoft.XMLDOM").CreateElement("b64")
		$a_01_1 = {64 61 74 61 54 79 70 65 20 3d 20 22 62 69 6e 2e 62 61 73 65 36 34 22 3a 20 2e 6e 6f 64 65 54 79 70 65 64 56 61 6c 75 65 } //01 00  dataType = "bin.base64": .nodeTypedValue
		$a_01_2 = {43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 50 61 74 68 68 20 26 20 22 53 63 72 69 70 74 2e 70 73 31 22 2c 20 54 72 75 65 29 } //01 00  CreateTextFile(Pathh & "Script.ps1", True)
		$a_01_3 = {43 3a 5c 55 73 65 72 73 5c 22 20 26 20 75 4e 61 6d 65 20 26 20 22 5c 41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 55 70 64 61 74 65 5c } //01 00  C:\Users\" & uName & "\AppData\Local\Microsoft\Windows\Update\
		$a_01_4 = {46 53 4f 32 2e 43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 50 61 74 68 68 20 26 20 22 55 70 64 61 74 65 72 2e 76 62 73 22 2c 20 54 72 75 65 29 } //00 00  FSO2.CreateTextFile(Pathh & "Updater.vbs", True)
	condition:
		any of ($a_*)
 
}
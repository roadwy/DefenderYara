
rule TrojanDownloader_O97M_Obfuse_SC_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.SC!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_03_0 = {3d 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 46 69 65 6c 64 73 2e 49 74 65 6d 28 90 02 03 29 2e 4f 4c 45 46 6f 72 6d 61 74 2e 4f 62 6a 65 63 74 2e 47 72 6f 75 70 4e 61 6d 65 90 00 } //01 00 
		$a_03_1 = {2e 49 74 65 6d 28 29 2e 44 6f 63 75 6d 65 6e 74 2e 41 70 70 6c 69 63 61 74 69 6f 6e 2e 53 68 65 6c 6c 45 78 65 63 75 74 65 20 90 02 20 2c 90 00 } //01 00 
		$a_01_2 = {22 43 3a 5c 57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 33 32 22 2c 20 4e 75 6c 6c 2c 20 30 20 2a 20 31 } //01 00  "C:\Windows\System32", Null, 0 * 1
		$a_03_3 = {4d 69 64 28 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 50 61 72 61 67 72 61 70 68 73 28 90 02 30 29 2e 52 61 6e 67 65 2e 54 65 78 74 20 26 20 22 22 2c 90 00 } //01 00 
		$a_03_4 = {4d 69 64 28 54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 50 61 72 61 67 72 61 70 68 73 28 90 02 20 29 2e 52 61 6e 67 65 2e 54 65 78 74 2c 20 90 02 10 2c 90 00 } //01 00 
		$a_01_5 = {3d 20 22 22 } //00 00  = ""
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_SC_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.SC!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,0b 00 0b 00 0b 00 00 01 00 "
		
	strings :
		$a_01_0 = {46 6f 72 20 45 61 63 68 20 70 72 6f 70 20 49 6e 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 42 75 69 6c 74 49 6e 44 6f 63 75 6d 65 6e 74 50 72 6f 70 65 72 74 69 65 73 } //01 00  For Each prop In ActiveDocument.BuiltInDocumentProperties
		$a_03_1 = {49 66 20 70 72 6f 70 2e 4e 61 6d 65 20 3d 20 22 90 02 10 22 20 54 68 65 6e 90 00 } //01 00 
		$a_03_2 = {66 6f 75 6e 64 5f 76 61 6c 75 65 20 3d 20 4d 69 64 28 70 72 6f 70 2e 56 61 6c 75 65 2c 20 90 02 02 29 90 00 } //01 00 
		$a_01_3 = {6f 72 69 67 5f 76 61 6c 20 3d 20 42 61 73 65 36 34 44 65 63 6f 64 65 28 66 6f 75 6e 64 5f 76 61 6c 75 65 29 } //01 00  orig_val = Base64Decode(found_value)
		$a_01_4 = {6f 72 69 67 5f 76 61 6c 20 3d 20 42 61 73 65 36 34 44 65 63 6f 64 65 28 6f 72 69 67 5f 76 61 6c 29 } //01 00  orig_val = Base64Decode(orig_val)
		$a_01_5 = {53 65 74 20 66 73 6f 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 63 72 69 70 74 69 6e 67 2e 46 69 6c 65 53 79 73 74 65 6d 4f 62 6a 65 63 74 22 29 } //01 00  Set fso = CreateObject("Scripting.FileSystemObject")
		$a_01_6 = {74 6d 70 5f 66 6f 6c 64 65 72 20 3d 20 66 73 6f 2e 47 65 74 53 70 65 63 69 61 6c 46 6f 6c 64 65 72 28 32 29 } //01 00  tmp_folder = fso.GetSpecialFolder(2)
		$a_01_7 = {74 6d 70 5f 6e 61 6d 65 20 3d 20 74 6d 70 5f 66 6f 6c 64 65 72 20 2b 20 22 5c 22 20 2b 20 66 73 6f 2e 47 65 74 54 65 6d 70 4e 61 6d 65 28 29 20 2b 20 22 2e 63 6d 64 22 } //01 00  tmp_name = tmp_folder + "\" + fso.GetTempName() + ".cmd"
		$a_01_8 = {53 65 74 20 66 20 3d 20 66 73 6f 2e 63 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 74 6d 70 5f 6e 61 6d 65 29 } //01 00  Set f = fso.createTextFile(tmp_name)
		$a_01_9 = {66 2e 57 72 69 74 65 20 28 6f 72 69 67 5f 76 61 6c 29 } //01 00  f.Write (orig_val)
		$a_01_10 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 2e 52 75 6e 20 74 6d 70 5f 6e 61 6d 65 2c 20 30 } //00 00  CreateObject("WScript.Shell").Run tmp_name, 0
	condition:
		any of ($a_*)
 
}
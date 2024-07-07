
rule TrojanDownloader_O97M_Obfuse_PBB_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PBB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 } //1 = CreateObject("wscript.shell")
		$a_01_1 = {2e 65 78 65 63 20 66 72 6d 2e 43 6f 6d 6d 61 6e 64 42 75 74 74 6f 6e 31 2e 54 61 67 20 26 20 22 20 63 3a 5c 75 73 65 72 73 5c 70 75 62 6c 69 63 5c 6d 61 69 6e 2e 68 74 61 } //1 .exec frm.CommandButton1.Tag & " c:\users\public\main.hta
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule TrojanDownloader_O97M_Obfuse_PBB_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PBB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {69 65 2e 4e 61 76 69 67 61 74 65 20 22 68 74 74 70 73 3a 2f 2f 70 61 73 74 65 62 69 6e 2e 63 6f 6d 2f 72 61 77 2f 50 4d 77 47 57 6b 6d 68 } //1 ie.Navigate "https://pastebin.com/raw/PMwGWkmh
		$a_00_1 = {44 69 6d 20 70 61 79 6c 6f 61 64 3a 20 70 61 79 6c 6f 61 64 20 3d 20 69 65 2e 44 6f 63 75 6d 65 6e 74 2e 42 6f 64 79 } //1 Dim payload: payload = ie.Document.Body
		$a_00_2 = {3d 20 45 6e 76 69 72 6f 6e 28 22 54 45 4d 50 22 29 20 26 20 22 5c 43 56 52 } //1 = Environ("TEMP") & "\CVR
		$a_00_3 = {6f 62 6a 46 53 4f 2e 44 65 6c 65 74 65 46 69 6c 65 20 70 } //1 objFSO.DeleteFile p
		$a_00_4 = {6f 62 6a 2e 44 6f 63 75 6d 65 6e 74 2e 41 70 70 6c 69 63 61 74 69 6f 6e 2e 53 68 65 6c 6c 45 78 65 63 75 74 65 20 22 72 75 6e 64 6c 6c 33 32 } //1 obj.Document.Application.ShellExecute "rundll32
		$a_00_5 = {6f 62 6a 46 53 4f 2e 43 72 65 61 74 65 54 65 78 74 46 69 6c 65 } //1 objFSO.CreateTextFile
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}
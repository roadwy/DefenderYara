
rule TrojanDownloader_O97M_Ursnif_BKH_MTB{
	meta:
		description = "TrojanDownloader:O97M/Ursnif.BKH!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {6e 61 6d 65 73 70 61 63 65 45 78 2e 65 78 65 63 20 66 72 6d 2e 43 6f 6d 6d 61 6e 64 42 75 74 74 6f 6e 31 2e 54 61 67 20 26 20 22 20 63 3a 5c 75 73 65 72 73 5c 70 75 62 6c 69 63 5c 6d 61 69 6e 2e 68 74 61 22 } //1 namespaceEx.exec frm.CommandButton1.Tag & " c:\users\public\main.hta"
		$a_01_1 = {73 63 72 69 70 74 20 3d 20 22 73 63 72 69 70 74 22 20 26 20 22 2e 22 } //1 script = "script" & "."
		$a_01_2 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 22 20 26 20 73 63 72 69 70 74 20 26 20 22 73 68 65 6c 6c 22 29 } //1 = CreateObject("w" & script & "shell")
		$a_01_3 = {43 61 6c 6c 20 66 72 6d 2e 43 6f 6d 6d 61 6e 64 42 75 74 74 6f 6e 31 5f 43 6c 69 63 6b } //1 Call frm.CommandButton1_Click
		$a_01_4 = {62 75 74 74 6f 6e 45 78 63 65 70 74 69 6f 6e 2e 41 70 70 65 6e 64 5f 33 } //1 buttonException.Append_3
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
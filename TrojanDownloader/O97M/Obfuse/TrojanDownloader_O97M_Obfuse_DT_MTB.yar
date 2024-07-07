
rule TrojanDownloader_O97M_Obfuse_DT_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.DT!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {53 63 72 69 70 74 69 6e 67 2e 46 69 6c 65 53 79 73 74 65 6d 4f 62 6a 65 63 74 22 } //1 Scripting.FileSystemObject"
		$a_00_1 = {4d 73 67 42 6f 78 20 22 66 69 6c 65 20 65 78 69 73 74 73 22 } //1 MsgBox "file exists"
		$a_00_2 = {63 70 6c 75 73 63 6f 6e 73 6f 6c 65 31 31 31 2e 6a 70 67 22 2c 20 54 72 75 65 29 } //1 cplusconsole111.jpg", True)
		$a_00_3 = {63 65 72 74 75 74 69 6c 20 2d 64 65 63 6f 64 65 20 63 70 6c 75 73 63 6f 6e 73 6f 6c 65 2e 74 78 74 } //1 certutil -decode cplusconsole.txt
		$a_00_4 = {53 68 65 6c 6c 20 22 63 6d 64 2e 65 78 65 20 2f 63 20 73 74 61 72 74 20 63 70 6c 75 73 63 6f 6e 73 6f 6c 65 2e 6a 70 67 22 } //1 Shell "cmd.exe /c start cplusconsole.jpg"
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}
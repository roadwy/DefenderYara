
rule TrojanDownloader_O97M_Obfuse_DW_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.DW!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {53 63 72 69 70 74 69 6e 67 2e 46 69 6c 65 53 79 73 74 65 6d 4f 62 6a 65 63 74 22 } //1 Scripting.FileSystemObject"
		$a_00_1 = {63 70 6c 75 73 63 6f 6e 73 6f 6c 65 2e 74 78 74 22 2c 20 54 72 75 65 } //1 cplusconsole.txt", True
		$a_00_2 = {2e 57 72 69 74 65 20 63 65 6c 6c 2e 56 61 6c 75 65 } //1 .Write cell.Value
		$a_00_3 = {63 65 72 74 75 74 69 6c 20 2d 64 65 63 6f 64 65 20 63 70 6c 75 73 63 6f 6e 73 6f 6c 65 2e 74 78 74 } //1 certutil -decode cplusconsole.txt
		$a_00_4 = {53 68 65 6c 6c 20 22 63 6d 64 2e 65 78 65 20 2f 63 20 73 74 61 72 74 20 63 70 6c 75 73 63 6f 6e 73 6f 6c 65 2e 6a 70 67 22 } //1 Shell "cmd.exe /c start cplusconsole.jpg"
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}
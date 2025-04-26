
rule TrojanDownloader_O97M_Obfuse_EH_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.EH!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_00_0 = {43 3a 5c 55 73 65 72 73 22 20 2b 20 22 5c 50 75 62 6c 69 63 } //1 C:\Users" + "\Public
		$a_00_1 = {43 61 6c 6c 20 53 68 65 6c 6c 28 22 63 6d 64 20 2f 63 20 63 6f 70 79 } //1 Call Shell("cmd /c copy
		$a_00_2 = {5c 6d 65 77 2e 64 6f 63 22 2c 20 76 62 48 69 64 65 29 } //1 \mew.doc", vbHide)
		$a_00_3 = {2b 20 22 5c 6d 65 77 2e 7a 69 70 22 2c 20 61 72 67 75 6d 65 6e 74 } //1 + "\mew.zip", argument
		$a_00_4 = {43 61 6c 6c 20 53 68 65 6c 6c 28 22 63 6d 64 20 2f 63 20 72 6d 64 69 72 20 2f 73 20 2f 71 } //1 Call Shell("cmd /c rmdir /s /q
		$a_00_5 = {5c 4d 65 77 5c 6c 75 61 2e 63 6d 64 } //1 \Mew\lua.cmd
		$a_00_6 = {5c 4d 65 77 5c 72 6f 77 2e 6c 75 61 } //1 \Mew\row.lua
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=7
 
}
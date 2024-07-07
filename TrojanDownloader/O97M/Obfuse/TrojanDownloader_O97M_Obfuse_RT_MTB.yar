
rule TrojanDownloader_O97M_Obfuse_RT_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.RT!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 } //1 CreateObject("wscript.shell")
		$a_01_1 = {43 61 6c 6c 20 62 63 36 35 30 38 37 39 2e 65 78 65 63 28 61 37 37 39 62 32 61 38 29 } //1 Call bc650879.exec(a779b2a8)
		$a_01_2 = {63 3a 5c 70 72 6f 67 72 61 6d 64 61 74 61 5c 70 72 65 76 69 65 77 2e 6a 70 65 67 } //1 c:\programdata\preview.jpeg
		$a_01_3 = {64 62 31 39 39 63 65 61 2e 4f 70 65 6e 20 22 47 45 54 22 2c 20 63 34 35 37 37 64 63 66 } //1 db199cea.Open "GET", c4577dcf
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_Obfuse_RT_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.RT!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {3d 20 49 73 4e 75 6d 65 72 69 63 28 22 22 29 } //1 = IsNumeric("")
		$a_03_1 = {2e 49 74 65 6d 28 29 2e 44 6f 63 75 6d 65 6e 74 2e 41 70 70 6c 69 63 61 74 69 6f 6e 2e 53 68 65 6c 6c 45 78 65 63 75 74 65 20 90 02 15 2c 90 00 } //1
		$a_01_2 = {26 20 52 65 70 6c 61 63 65 28 22 68 22 2c 20 22 68 22 2c 20 22 48 22 29 20 5f } //1 & Replace("h", "h", "H") _
		$a_03_3 = {3d 20 52 65 70 6c 61 63 65 28 90 02 15 2c 20 90 02 15 2c 20 22 22 29 90 00 } //1
		$a_01_4 = {26 20 22 34 } //1 & "4
		$a_01_5 = {26 20 22 33 } //1 & "3
		$a_01_6 = {26 20 22 32 } //1 & "2
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}
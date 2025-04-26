
rule TrojanDownloader_O97M_RevengeRAT_NGE_MTB{
	meta:
		description = "TrojanDownloader:O97M/RevengeRAT.NGE!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {27 68 74 74 70 73 3a 2f 2f 70 74 2e 74 65 78 74 62 69 6e 2e 6e 65 74 2f 64 6f 77 6e 6c 6f 61 64 2f 78 37 73 66 36 74 32 64 67 76 27 20 29 20 3b } //1 'https://pt.textbin.net/download/x7sf6t2dgv' ) ;
		$a_01_1 = {43 61 6c 6c 20 53 68 65 6c 6c 28 22 70 6f 77 22 20 26 20 22 65 72 73 22 20 26 20 22 68 65 6c 6c 2e 65 78 65 20 2d 63 6f 6d 6d 61 6e 64 20 22 20 26 20 43 69 67 76 4c 20 26 20 22 20 3b 20 65 78 69 74 20 22 2c 20 76 62 48 69 64 65 29 } //1 Call Shell("pow" & "ers" & "hell.exe -command " & CigvL & " ; exit ", vbHide)
		$a_01_2 = {73 75 62 61 75 74 6f 5f 6f 70 65 6e 28 29 } //1 subauto_open()
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
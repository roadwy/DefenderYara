
rule TrojanDownloader_O97M_Powdow_VRB_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.VRB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 75 62 20 41 75 74 6f 5f 4f 70 65 6e 28 29 } //1 Sub Auto_Open()
		$a_01_1 = {28 20 27 68 74 74 70 73 3a 2f 2f 70 74 2e 74 65 78 74 62 69 6e 2e 6e 65 74 2f 64 6f 77 6e 6c 6f 61 64 2f 69 74 6d 31 64 6b 67 7a 37 63 27 20 29 } //1 ( 'https://pt.textbin.net/download/itm1dkgz7c' )
		$a_01_2 = {77 73 63 72 69 70 74 2e 65 78 65 20 78 2e 76 62 73 } //1 wscript.exe x.vbs
		$a_01_3 = {43 61 6c 6c 20 53 68 65 6c 6c 28 22 70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 63 6f 6d 6d 61 6e 64 20 22 20 26 20 67 49 72 4e 6f 20 26 20 22 20 3b 20 65 78 69 74 20 22 2c 20 76 62 48 69 64 65 29 } //1 Call Shell("powershell.exe -command " & gIrNo & " ; exit ", vbHide)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
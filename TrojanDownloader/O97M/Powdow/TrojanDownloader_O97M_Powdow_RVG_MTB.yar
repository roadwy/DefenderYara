
rule TrojanDownloader_O97M_Powdow_RVG_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RVG!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {4b 6b 20 3d 20 22 70 6f 77 65 72 73 68 65 6c 6c 20 2d 6e 6f 50 20 2d 73 74 61 20 2d 77 20 31 20 2d 65 6e 63 20 20 53 51 42 6d 41 43 67 41 4a 41 42 51 41 46 4d 41 56 67 22 } //1 Kk = "powershell -noP -sta -w 1 -enc  SQBmACgAJABQAFMAVg"
		$a_01_1 = {57 67 67 52 4b 20 3d 20 53 74 72 52 65 76 65 72 73 65 28 22 20 63 6e 65 2d 20 31 20 77 2d 20 61 74 73 2d 20 50 6f 6e 2d 20 6c 6c 65 68 73 72 65 77 6f 70 22 29 } //1 WggRK = StrReverse(" cne- 1 w- ats- Pon- llehsrewop")
		$a_01_2 = {61 73 64 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 } //1 asd = CreateObject("WScript.Shell")
		$a_03_3 = {61 73 64 2e 52 75 6e 20 28 [0-05] 29 } //1
		$a_01_4 = {41 75 74 6f 43 6c 6f 73 65 28 29 } //1 AutoClose()
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}
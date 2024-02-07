
rule TrojanDownloader_Win32_Seraph_PAAG_MTB{
	meta:
		description = "TrojanDownloader:Win32/Seraph.PAAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {61 48 52 30 63 44 6f 76 4c 32 6c 74 5a 32 4e 68 59 32 68 6c 4c 6d 4e 73 62 33 56 6b 63 32 56 79 64 6d 6c 6a 5a 58 4e 6b 5a 58 5a 6a 4c 6e 52 72 4c 33 42 70 59 33 52 31 63 6d 56 7a 63 79 38 79 4d 44 49 7a 4c 77 3d 3d } //01 00  aHR0cDovL2ltZ2NhY2hlLmNsb3Vkc2VydmljZXNkZXZjLnRrL3BpY3R1cmVzcy8yMDIzLw==
		$a_01_1 = {69 6d 67 63 61 63 68 65 2e 63 6c 6f 75 64 73 65 72 76 69 63 65 73 64 65 76 63 2e 74 6b 2f 70 69 63 74 75 72 65 73 73 2f 32 30 32 33 2f 52 44 53 76 33 38 2e 64 6c 6c } //00 00  imgcache.cloudservicesdevc.tk/picturess/2023/RDSv38.dll
	condition:
		any of ($a_*)
 
}
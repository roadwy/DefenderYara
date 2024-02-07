
rule TrojanDownloader_O97M_Qakbot_VA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.VA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 67 76 6e 70 73 64 } //01 00  C:\gvnpsd
		$a_01_1 = {5c 62 72 61 76 61 67 2e 65 78 65 } //01 00  \bravag.exe
		$a_01_2 = {4a 4a 43 43 43 4a 4a } //01 00  JJCCCJJ
		$a_01_3 = {52 6f 75 74 } //01 00  Rout
		$a_01_4 = {65 78 70 6c } //01 00  expl
		$a_01_5 = {55 52 4c 44 6f 77 6e } //00 00  URLDown
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Qakbot_VA_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.VA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {75 72 6c 6d 6f 6e } //01 00  urlmon
		$a_00_1 = {65 6c 69 78 65 72 64 69 67 69 74 61 6c 6c 2e 63 6f 6d 2f 64 73 2f 90 02 0f 2e 67 69 66 90 00 } //01 00 
		$a_00_2 = {43 3a 5c 65 72 76 69 6f 5c 63 6f 70 72 2e 72 73 67 73 } //00 00  C:\ervio\copr.rsgs
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Qakbot_VA_MTB_3{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.VA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,0c 00 0c 00 04 00 00 0a 00 "
		
	strings :
		$a_03_0 = {6a 6f 6f 73 74 70 69 65 74 65 72 2e 63 6f 6d 2f 64 73 2f 90 02 0f 2e 67 69 66 90 00 } //01 00 
		$a_00_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //01 00  DllRegisterServer
		$a_00_2 = {72 75 6e 64 6c 6c 33 32 } //01 00  rundll32
		$a_00_3 = {43 3a 5c 65 72 76 69 6f 5c 63 6f 70 72 2e 72 73 67 73 } //00 00  C:\ervio\copr.rsgs
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Qakbot_VA_MTB_4{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.VA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,0c 00 0c 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 4a 49 4f 4c 41 53 2e 52 52 54 54 4f 4f 4b 4b } //0a 00  \JIOLAS.RRTTOOKK
		$a_03_1 = {6b 61 6e 67 61 72 6f 6f 2e 74 65 63 68 6f 6e 65 78 74 2e 63 6f 6d 2f 90 02 0f 2f 90 02 0f 2e 6a 70 67 90 00 } //01 00 
		$a_03_2 = {62 61 63 68 73 2e 67 72 6f 75 70 2f 90 02 0f 2f 90 02 0f 2e 6a 70 67 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Qakbot_VA_MTB_5{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.VA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,0d 00 0d 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {75 72 6c 6d 6f 6e } //01 00  urlmon
		$a_00_1 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //01 00  URLDownloadToFileA
		$a_00_2 = {43 3a 5c 49 6e 74 65 6c 43 6f 6d 70 61 6e 79 5c 4a 49 4f 4c 41 53 2e 52 52 54 54 4f 4f 4b 4b } //0a 00  C:\IntelCompany\JIOLAS.RRTTOOKK
		$a_03_3 = {2e 63 6f 6d 2f 90 02 0f 2f 35 35 35 35 35 35 35 35 35 35 35 2e 6a 70 67 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Qakbot_VA_MTB_6{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.VA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {6c 73 78 2e 31 5c 61 74 61 64 6d 61 72 67 6f 72 70 5c 3a 63 } //01 00  lsx.1\atadmargorp\:c
		$a_01_1 = {6d 6f 63 2e 31 5c 61 74 61 64 6d 61 72 67 6f 72 70 5c 3a 63 } //01 00  moc.1\atadmargorp\:c
		$a_01_2 = {65 78 65 2e 63 69 6d 77 5c 6d 65 62 77 5c 32 33 6d 65 74 73 79 73 5c 73 77 6f 64 6e 69 77 5c 3a 63 } //01 00  exe.cimw\mebw\23metsys\swodniw\:c
		$a_03_3 = {2e 72 75 6e 20 90 02 0f 28 90 02 0f 29 20 26 20 90 02 0f 28 22 63 6f 6d 6d 65 6e 74 73 22 29 90 00 } //01 00 
		$a_03_4 = {46 69 6c 65 43 6f 70 79 28 90 02 0f 28 90 02 0f 29 2c 20 90 02 0f 28 90 02 0f 29 29 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Qakbot_VA_MTB_7{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.VA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,0c 00 0c 00 06 00 00 01 00 "
		
	strings :
		$a_03_0 = {74 61 6b 69 73 61 61 74 2e 63 6f 6d 2f 90 02 0f 2f 90 02 0f 2e 6a 70 67 90 00 } //01 00 
		$a_03_1 = {61 74 65 6c 69 65 72 73 70 75 7a 7a 6c 65 2e 63 6f 6d 2f 90 02 0f 2f 90 02 0f 2e 6a 70 67 90 00 } //01 00 
		$a_03_2 = {77 77 77 2e 64 6f 6d 6f 70 6f 72 74 75 67 61 6c 2e 63 6f 6d 2f 90 02 0f 2f 90 02 0f 2e 6a 70 67 90 00 } //01 00 
		$a_03_3 = {6d 61 65 73 74 72 6f 63 61 72 6c 6f 74 2e 6e 65 74 2f 90 02 0f 2f 90 02 0f 2e 6a 70 67 90 00 } //01 00 
		$a_03_4 = {67 61 6e 65 73 61 6e 64 2e 63 6f 6d 2f 90 02 0f 2f 90 02 0f 2e 6a 70 67 90 00 } //0a 00 
		$a_01_5 = {43 3a 5c 49 6e 74 65 6c 43 6f 6d 70 61 6e 79 5c 4a 49 4f 4c 41 53 2e 52 52 54 54 4f 4f 4b 4b } //00 00  C:\IntelCompany\JIOLAS.RRTTOOKK
	condition:
		any of ($a_*)
 
}
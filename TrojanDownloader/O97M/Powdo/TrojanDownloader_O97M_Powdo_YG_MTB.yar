
rule TrojanDownloader_O97M_Powdo_YG_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdo.YG!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 75 72 77 2e 63 72 65 61 74 65 20 22 72 75 6e 64 6c 6c 33 32 20 7a 69 70 66 6c 64 72 2e 64 6c 6c 2c 52 6f 75 74 65 54 68 65 43 61 6c 6c 20 63 3a 5c 77 6f 72 64 70 72 65 73 73 5c 61 62 6f 75 74 31 2e 76 62 73 } //01 00  curw.create "rundll32 zipfldr.dll,RouteTheCall c:\wordpress\about1.vbs
		$a_01_1 = {6e 2e 43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 22 63 3a 5c 77 6f 72 64 70 72 65 73 73 5c 61 62 6f 75 74 31 2e 76 62 73 } //00 00  n.CreateTextFile("c:\wordpress\about1.vbs
	condition:
		any of ($a_*)
 
}
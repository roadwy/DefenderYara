
rule TrojanDownloader_O97M_Qakbot_PUB_MTB{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.PUB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {4a 4a 43 43 43 4a 4a } //01 00  JJCCCJJ
		$a_00_1 = {4a 4a 43 43 42 42 } //01 00  JJCCBB
		$a_00_2 = {7a 69 70 66 6c 64 72 } //01 00  zipfldr
		$a_00_3 = {68 74 74 70 73 3a 2f 2f 71 31 73 30 6f 63 69 34 39 6a 6f 2e 78 79 7a 2f 67 75 74 70 61 67 65 2e 70 68 70 } //01 00  https://q1s0oci49jo.xyz/gutpage.php
		$a_00_4 = {43 3a 5c 72 6f 69 77 6e 73 } //01 00  C:\roiwns
		$a_00_5 = {5c 64 73 66 73 65 69 2e 65 78 65 } //00 00  \dsfsei.exe
	condition:
		any of ($a_*)
 
}
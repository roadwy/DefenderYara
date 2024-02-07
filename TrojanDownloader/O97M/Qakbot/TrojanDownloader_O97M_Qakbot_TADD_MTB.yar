
rule TrojanDownloader_O97M_Qakbot_TADD_MTB{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.TADD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 22 2e 2e 5c 43 65 6c 6f 64 2e 77 61 63 } //01 00  = "..\Celod.wac
		$a_01_1 = {3d 20 22 2e 2e 5c 43 65 6c 6f 64 2e 77 61 63 22 20 26 20 22 31 } //01 00  = "..\Celod.wac" & "1
		$a_01_2 = {3d 20 22 2e 2e 5c 43 65 6c 6f 64 2e 77 61 63 22 20 26 20 22 32 } //01 00  = "..\Celod.wac" & "2
		$a_01_3 = {2e 64 22 20 26 20 22 61 22 20 26 20 22 74 22 } //00 00  .d" & "a" & "t"
	condition:
		any of ($a_*)
 
}

rule TrojanDownloader_O97M_Qakbot_TADD_MTB{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.TADD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {3d 20 22 2e 2e 5c 43 65 6c 6f 64 2e 77 61 63 } //1 = "..\Celod.wac
		$a_01_1 = {3d 20 22 2e 2e 5c 43 65 6c 6f 64 2e 77 61 63 22 20 26 20 22 31 } //1 = "..\Celod.wac" & "1
		$a_01_2 = {3d 20 22 2e 2e 5c 43 65 6c 6f 64 2e 77 61 63 22 20 26 20 22 32 } //1 = "..\Celod.wac" & "2
		$a_01_3 = {2e 64 22 20 26 20 22 61 22 20 26 20 22 74 22 } //1 .d" & "a" & "t"
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
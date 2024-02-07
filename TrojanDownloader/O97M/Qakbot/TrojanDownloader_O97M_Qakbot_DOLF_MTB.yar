
rule TrojanDownloader_O97M_Qakbot_DOLF_MTB{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.DOLF!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 22 68 22 20 26 20 22 74 74 22 20 26 20 22 70 22 20 26 20 22 3a 2f 22 20 26 20 22 2f 31 39 30 2e 31 34 2e 33 37 2e 32 30 32 2f } //01 00  = "h" & "tt" & "p" & ":/" & "/190.14.37.202/
		$a_01_1 = {3d 20 22 68 22 20 26 20 22 74 74 22 20 26 20 22 70 22 20 26 20 22 3a 2f 22 20 26 20 22 2f 31 38 35 2e 32 34 34 2e 31 35 30 2e 31 37 34 2f } //01 00  = "h" & "tt" & "p" & ":/" & "/185.244.150.174/
		$a_01_2 = {2d 73 69 6c 65 6e 74 20 2e 2e 5c 43 65 6c 6f 64 2e 77 61 63 } //01 00  -silent ..\Celod.wac
		$a_01_3 = {3d 20 4e 6f 6c 65 72 74 2e 4c 61 62 65 6c 35 2e 43 61 70 74 69 6f 6e 20 26 20 22 31 } //00 00  = Nolert.Label5.Caption & "1
	condition:
		any of ($a_*)
 
}
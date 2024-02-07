
rule TrojanDownloader_O97M_Qakbot_NQRZ_MTB{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.NQRZ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 22 2e 2e 5c 43 65 6c 6f 64 2e 77 61 63 31 } //01 00  = "..\Celod.wac1
		$a_01_1 = {28 49 39 2c 49 31 30 26 4a 31 30 2c 49 31 31 2c 49 31 32 2c 2c 31 2c 39 29 } //01 00  (I9,I10&J10,I11,I12,,1,9)
		$a_01_2 = {3d 20 22 2e 64 22 20 26 20 22 61 22 20 26 20 22 74 } //01 00  = ".d" & "a" & "t
		$a_01_3 = {3d 20 55 73 65 72 46 6f 72 6d 32 2e 4c 61 62 65 6c 33 2e 43 61 70 74 69 6f 6e } //01 00  = UserForm2.Label3.Caption
		$a_01_4 = {2e 46 6f 6e 74 2e 43 6f 6c 6f 72 20 3d 20 76 62 57 68 69 74 65 } //00 00  .Font.Color = vbWhite
	condition:
		any of ($a_*)
 
}
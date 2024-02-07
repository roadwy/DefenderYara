
rule TrojanDownloader_O97M_Qakbot_NQRX_MTB{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.NQRX!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 52 61 6e 67 65 28 22 48 32 35 22 29 20 3d 20 55 73 65 72 46 6f 72 6d 32 2e 4c 61 62 65 6c 33 2e 43 61 70 74 69 6f 6e } //01 00  .Range("H25") = UserForm2.Label3.Caption
		$a_01_1 = {72 65 67 73 76 72 33 32 20 2d 73 69 6c 65 6e 74 20 2e 2e 5c 44 72 65 7a 64 2e 72 65 64 } //01 00  regsvr32 -silent ..\Drezd.red
		$a_01_2 = {28 49 39 2c 49 31 30 26 4a 31 30 2c 49 31 31 2c 49 31 32 2c 2c 31 2c 39 29 } //01 00  (I9,I10&J10,I11,I12,,1,9)
		$a_01_3 = {42 79 75 6b 69 6c 6f 73 } //01 00  Byukilos
		$a_01_4 = {2e 46 6f 6e 74 2e 43 6f 6c 6f 72 20 3d 20 76 62 57 68 69 74 65 } //00 00  .Font.Color = vbWhite
	condition:
		any of ($a_*)
 
}
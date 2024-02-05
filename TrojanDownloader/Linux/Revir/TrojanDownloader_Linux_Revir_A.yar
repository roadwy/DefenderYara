
rule TrojanDownloader_Linux_Revir_A{
	meta:
		description = "TrojanDownloader:Linux/Revir.A,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 75 72 6c 20 2d 6f 20 2f 74 6d 70 2f 75 70 64 74 64 61 74 61 } //03 00 
		$a_03_1 = {55 89 e5 83 ec 18 e8 8b ff ff ff c7 44 24 04 90 01 02 00 00 a1 28 20 00 00 89 04 24 e8 a3 00 00 00 c7 04 24 90 01 02 00 00 e8 c7 00 00 00 c7 44 24 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
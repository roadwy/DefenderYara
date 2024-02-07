
rule TrojanDownloader_BAT_Seraph_PAAL_MTB{
	meta:
		description = "TrojanDownloader:BAT/Seraph.PAAL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 00 2f 00 76 00 75 00 6c 00 63 00 61 00 6e 00 6f 00 2d 00 67 00 72 00 6f 00 75 00 70 00 2e 00 63 00 6f 00 6d 00 2f 00 77 00 65 00 73 00 74 00 2f 00 5a 00 6d 00 6b 00 64 00 6c 00 6b 00 2e 00 64 00 61 00 74 00 } //01 00  //vulcano-group.com/west/Zmkdlk.dat
		$a_01_1 = {24 63 62 65 37 39 64 62 35 2d 64 66 31 39 2d 34 66 30 32 2d 62 61 61 66 2d 30 35 34 64 37 65 34 37 38 35 38 65 } //00 00  $cbe79db5-df19-4f02-baaf-054d7e47858e
	condition:
		any of ($a_*)
 
}
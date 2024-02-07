
rule TrojanDownloader_BAT_AveMaria_RDB_MTB{
	meta:
		description = "TrojanDownloader:BAT/AveMaria.RDB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 36 38 61 33 39 38 33 2d 35 38 37 64 2d 34 65 35 66 2d 61 64 35 33 2d 39 61 38 62 38 33 63 30 35 63 31 34 } //01 00  c68a3983-587d-4e5f-ad53-9a8b83c05c14
		$a_01_1 = {73 00 70 00 62 00 2d 00 67 00 61 00 6e 00 2e 00 72 00 75 00 2f 00 70 00 61 00 6e 00 65 00 6c 00 2f 00 75 00 70 00 6c 00 6f 00 61 00 64 00 73 00 2f 00 48 00 7a 00 62 00 64 00 7a 00 6a 00 6f 00 2e 00 70 00 6e 00 67 00 } //01 00  spb-gan.ru/panel/uploads/Hzbdzjo.png
		$a_01_2 = {49 00 6c 00 79 00 6f 00 62 00 64 00 76 00 68 00 6e 00 6e 00 70 00 71 00 67 00 6b 00 69 00 6e 00 76 00 6f 00 66 00 6b 00 63 00 2e 00 4f 00 66 00 69 00 65 00 6a 00 6b 00 6f 00 64 00 66 00 79 00 6e 00 67 00 } //01 00  Ilyobdvhnnpqgkinvofkc.Ofiejkodfyng
		$a_01_3 = {41 00 68 00 79 00 66 00 65 00 69 00 6e 00 62 00 74 00 78 00 75 00 65 00 } //00 00  Ahyfeinbtxue
	condition:
		any of ($a_*)
 
}
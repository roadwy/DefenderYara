
rule TrojanDownloader_O97M_Emotet_PDK_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.PDK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {3a 2f 2f 67 6f 67 6c 6f 62 65 74 72 61 76 65 6c 2e 63 6f 6d 2f 77 70 2d 61 64 6d 69 6e 2f 31 4f 31 54 6a 72 39 6e 48 42 56 2f } //01 00  ://goglobetravel.com/wp-admin/1O1Tjr9nHBV/
		$a_01_1 = {3a 2f 2f 70 61 6b 69 73 74 61 6e 6e 61 6b 6c 69 79 65 2e 63 6f 6d 2f 77 70 2d 61 64 6d 69 6e 2f 64 79 66 41 64 52 6b 76 37 2f } //01 00  ://pakistannakliye.com/wp-admin/dyfAdRkv7/
		$a_01_2 = {3a 2f 2f 73 70 69 6e 6f 66 66 79 61 72 6e 73 68 6f 70 2e 63 6f 6d 2f 63 6f 6e 74 65 6e 74 2f 59 51 6c 6d 62 4c 61 42 2f } //01 00  ://spinoffyarnshop.com/content/YQlmbLaB/
		$a_01_3 = {3a 2f 2f 6d 75 72 74 6a 69 7a 69 6e 64 75 73 74 72 79 2e 63 6f 6d 2f 77 70 2d 63 6f 6e 74 65 6e 74 2f 79 49 36 2f } //01 00  ://murtjizindustry.com/wp-content/yI6/
		$a_01_4 = {3a 2f 2f 6e 61 7a 72 75 6c 74 68 65 6b 69 6e 67 2e 63 6f 6d 2f 77 70 2d 69 6e 63 6c 75 64 65 73 2f 4c 5a 2f } //01 00  ://nazrultheking.com/wp-includes/LZ/
		$a_01_5 = {3a 2f 2f 68 6f 73 73 61 69 62 6d 6f 6a 61 6d 6d 65 6c 2e 63 6f 6d 2f 77 70 2d 63 6f 6e 74 65 6e 74 2f 71 46 50 67 68 70 72 57 4f 30 4f 4e 78 4c 46 41 35 64 2f } //00 00  ://hossaibmojammel.com/wp-content/qFPghprWO0ONxLFA5d/
	condition:
		any of ($a_*)
 
}

rule Trojan_AndroidOS_Downloader_A_MTB{
	meta:
		description = "Trojan:AndroidOS/Downloader.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {4c 63 6f 6d 2f 65 78 61 6d 70 6c 65 2f 64 65 63 6f 79 2f 41 63 63 65 73 62 69 6c 69 74 79 53 65 72 76 69 63 65 3b } //01 00  Lcom/example/decoy/AccesbilityService;
		$a_00_1 = {63 6f 6d 2e 61 62 64 75 6c 72 61 75 66 2e 66 69 6c 65 6d 61 6e 61 67 65 72 } //01 00  com.abdulrauf.filemanager
		$a_00_2 = {2f 4f 76 65 72 6c 61 79 53 65 72 76 69 63 65 3b } //01 00  /OverlayService;
		$a_00_3 = {5a 47 46 73 64 6d 6c 72 4c 6e 4e 35 63 33 52 6c 62 53 35 45 5a 58 68 44 62 47 46 7a 63 30 78 76 59 57 52 6c 63 67 3d 3d } //00 00  ZGFsdmlrLnN5c3RlbS5EZXhDbGFzc0xvYWRlcg==
	condition:
		any of ($a_*)
 
}
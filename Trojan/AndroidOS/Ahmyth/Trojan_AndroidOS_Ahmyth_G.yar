
rule Trojan_AndroidOS_Ahmyth_G{
	meta:
		description = "Trojan:AndroidOS/Ahmyth.G,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 03 00 00 04 00 "
		
	strings :
		$a_01_0 = {38 30 38 37 36 64 64 35 2e 73 68 6f 70 } //02 00  80876dd5.shop
		$a_01_1 = {55 50 4c 4f 41 44 5f 46 49 4c 45 5f 41 46 54 45 52 5f 44 41 54 45 } //02 00  UPLOAD_FILE_AFTER_DATE
		$a_01_2 = {2f 73 65 72 76 69 63 65 74 65 61 73 6f 66 74 } //00 00  /serviceteasoft
	condition:
		any of ($a_*)
 
}
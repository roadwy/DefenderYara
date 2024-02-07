
rule Trojan_AndroidOS_SpyRax_DS_MTB{
	meta:
		description = "Trojan:AndroidOS/SpyRax.DS!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_00_0 = {73 64 63 61 72 64 2f 2e 66 75 63 6b } //01 00  sdcard/.fuck
		$a_00_1 = {53 49 4d 41 4e 44 53 44 43 41 52 44 49 4e 46 4f } //01 00  SIMANDSDCARDINFO
		$a_00_2 = {42 65 67 69 6e 67 20 75 70 6c 6f 61 64 20 64 61 74 61 2e 2e 2e } //01 00  Beging upload data...
		$a_00_3 = {47 45 54 5f 43 41 4c 4c 4c 4f 47 53 } //01 00  GET_CALLLOGS
		$a_00_4 = {72 6d 20 2d 72 20 2f 64 61 74 61 2f 64 61 74 61 2f 63 6f 6d 2e 74 65 6e 63 65 6e 74 2e 6d 6f 62 69 6c 65 71 71 } //01 00  rm -r /data/data/com.tencent.mobileqq
		$a_00_5 = {47 45 54 5f 43 4f 4e 54 43 41 54 53 } //01 00  GET_CONTCATS
		$a_00_6 = {65 6d 61 69 6c 62 6f 64 79 2e 64 62 } //00 00  emailbody.db
	condition:
		any of ($a_*)
 
}
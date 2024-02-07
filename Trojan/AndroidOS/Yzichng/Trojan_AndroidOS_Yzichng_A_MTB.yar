
rule Trojan_AndroidOS_Yzichng_A_MTB{
	meta:
		description = "Trojan:AndroidOS/Yzichng.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 02 00 "
		
	strings :
		$a_00_0 = {61 70 69 2d 72 73 73 6f 63 6b 73 2e 79 6f 75 7a 69 63 68 65 6e 67 2e 6e 65 74 2f 61 70 69 2f 73 6f 63 6b 73 43 6f 6e 66 69 67 } //01 00  api-rssocks.youzicheng.net/api/socksConfig
		$a_00_1 = {63 68 6d 6f 64 20 37 37 37 20 2f 64 61 74 61 2f 64 61 74 61 2f 25 73 2f 66 69 6c 65 73 2f 72 73 73 6f 63 6b 73 } //01 00  chmod 777 /data/data/%s/files/rssocks
		$a_00_2 = {2f 50 6f 73 74 53 74 68 53 65 72 76 69 63 65 3b } //01 00  /PostSthService;
		$a_00_3 = {69 63 6f 6e 48 69 64 65 } //00 00  iconHide
		$a_00_4 = {5d 04 00 } //00 a5 
	condition:
		any of ($a_*)
 
}
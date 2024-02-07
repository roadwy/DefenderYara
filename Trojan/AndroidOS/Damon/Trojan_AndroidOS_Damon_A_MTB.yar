
rule Trojan_AndroidOS_Damon_A_MTB{
	meta:
		description = "Trojan:AndroidOS/Damon.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {67 65 74 44 61 6d 6f 6e 53 65 72 76 69 63 65 } //01 00  getDamonService
		$a_00_1 = {73 74 61 72 74 44 61 6d 6f 6e 53 65 72 76 69 63 65 } //01 00  startDamonService
		$a_00_2 = {77 65 62 73 65 72 76 69 63 65 2e 77 65 62 78 6d 6c 2e 63 6f 6d 2e 63 6e 2f 77 65 62 73 65 72 76 69 63 65 73 2f 44 6f 6d 65 73 74 69 63 41 69 72 6c 69 6e 65 2e 61 73 6d 78 } //01 00  webservice.webxml.com.cn/webservices/DomesticAirline.asmx
		$a_00_3 = {69 6e 73 74 61 6c 6c 41 70 6b } //01 00  installApk
		$a_00_4 = {64 6f 77 6e 6c 6f 61 64 41 70 6b } //00 00  downloadApk
	condition:
		any of ($a_*)
 
}

rule Trojan_AndroidOS_SmsSend_A{
	meta:
		description = "Trojan:AndroidOS/SmsSend.A,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 52 45 4e 41 20 45 58 43 49 54 45 } //01 00  ARENA EXCITE
		$a_01_1 = {47 41 4c 20 43 41 4e 54 49 4b } //01 00  GAL CANTIK
		$a_01_2 = {50 70 61 67 65 72 6f 6d 6f } //01 00  Ppageromo
		$a_01_3 = {4f 6e 74 6b 65 6e 6e 69 6e 67 44 69 73 } //01 00  OntkenningDis
		$a_01_4 = {4f 4e 20 47 41 4d 45 20 4b 49 53 53 } //01 00  ON GAME KISS
		$a_01_5 = {47 49 52 4c 20 43 41 4e 54 49 4b } //00 00  GIRL CANTIK
	condition:
		any of ($a_*)
 
}
rule Trojan_AndroidOS_SmsSend_A_2{
	meta:
		description = "Trojan:AndroidOS/SmsSend.A,SIGNATURE_TYPE_DEXHSTR_EXT,08 00 08 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {2f 57 45 42 2d 49 4e 46 2f 70 61 67 65 73 2f 70 6c 61 79 2f 77 61 70 33 2f 62 69 6c 6c 2e 6a 73 70 70 } //02 00  /WEB-INF/pages/play/wap3/bill.jspp
		$a_01_1 = {77 61 70 42 69 6c 6c 55 72 6c } //02 00  wapBillUrl
		$a_01_2 = {2f 77 61 70 2f 6e 31 30 33 34 35 33 33 32 64 32 63 35 30 32 31 31 31 31 32 35 2e 6a 73 70 } //02 00  /wap/n10345332d2c502111125.jsp
		$a_01_3 = {77 61 70 41 66 74 65 72 4d 69 67 75 53 64 6b 53 75 63 } //00 00  wapAfterMiguSdkSuc
	condition:
		any of ($a_*)
 
}
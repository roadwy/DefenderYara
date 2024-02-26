
rule Trojan_BAT_SnakeKeyLogger_RDAH_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeyLogger.RDAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {45 52 50 52 65 70 6f 72 74 55 74 69 6c 73 } //01 00  ERPReportUtils
		$a_01_1 = {45 78 61 6d 70 6c 65 } //01 00  Example
		$a_01_2 = {42 6f 6c 6b 76 61 64 7a 65 } //01 00  Bolkvadze
		$a_01_3 = {46 61 63 74 53 61 6c 65 73 } //00 00  FactSales
	condition:
		any of ($a_*)
 
}
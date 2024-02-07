
rule Trojan_BAT_AveMariaRAT_RPT_MTB{
	meta:
		description = "Trojan:BAT/AveMariaRAT.RPT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_03_0 = {62 00 6c 00 75 00 65 00 63 00 6f 00 76 00 65 00 72 00 74 00 72 00 61 00 64 00 69 00 6e 00 67 00 2e 00 63 00 6f 00 6d 00 90 02 20 2e 00 74 00 78 00 74 00 90 00 } //01 00 
		$a_01_1 = {64 00 6c 00 6c 00 2e 00 74 00 78 00 74 00 } //01 00  dll.txt
		$a_01_2 = {47 65 74 54 79 70 65 } //01 00  GetType
		$a_01_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_01_4 = {43 6f 6e 76 65 72 74 } //01 00  Convert
		$a_01_5 = {47 65 74 52 65 73 70 6f 6e 73 65 53 74 72 65 61 6d } //01 00  GetResponseStream
		$a_01_6 = {57 65 62 52 65 71 75 65 73 74 } //00 00  WebRequest
	condition:
		any of ($a_*)
 
}
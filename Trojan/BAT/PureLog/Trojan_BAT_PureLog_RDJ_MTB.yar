
rule Trojan_BAT_PureLog_RDJ_MTB{
	meta:
		description = "Trojan:BAT/PureLog.RDJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {41 37 44 30 37 32 45 34 2d 35 37 43 39 2d 34 38 46 31 2d 41 39 45 32 2d 41 45 35 38 44 46 45 42 31 37 36 43 } //1 A7D072E4-57C9-48F1-A9E2-AE58DFEB176C
		$a_01_1 = {5a 65 72 6f 42 79 74 65 39 34 33 } //1 ZeroByte943
		$a_01_2 = {5a 65 72 6f 62 79 74 65 39 38 35 31 } //1 Zerobyte9851
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
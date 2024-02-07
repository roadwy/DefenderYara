
rule Trojan_AndroidOS_Spynote_H_MTB{
	meta:
		description = "Trojan:AndroidOS/Spynote.H!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {47 50 53 43 41 4e } //01 00  GPSCAN
		$a_00_1 = {63 6f 6d 2e 61 6e 64 73 63 61 6e 2e 62 65 74 61 72 2e 63 61 6c 63 6f 6c 61 74 6f 72 } //01 00  com.andscan.betar.calcolator
		$a_00_2 = {57 61 63 6b 4d 65 55 70 4a 6f 62 } //01 00  WackMeUpJob
		$a_00_3 = {4d 61 69 6e 52 65 66 6c 65 63 74 6f 72 53 63 61 6e } //01 00  MainReflectorScan
		$a_00_4 = {61 63 6f 6d 65 6c 6f 74 6f 72 } //00 00  acomelotor
	condition:
		any of ($a_*)
 
}
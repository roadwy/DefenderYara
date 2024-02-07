
rule Trojan_AndroidOS_Cynos_A{
	meta:
		description = "Trojan:AndroidOS/Cynos.A,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {53 4d 53 4e 55 4d 42 45 52 5f 51 49 58 49 4e 54 4f 4e 47 } //01 00  SMSNUMBER_QIXINTONG
		$a_00_1 = {55 52 4c 5f 55 50 53 44 4b 4f 4e 4c 49 4e 45 54 49 4d 45 4c 4f 47 } //01 00  URL_UPSDKONLINETIMELOG
		$a_00_2 = {44 45 56 49 43 45 49 4e 46 4f 4b 45 59 5f 52 45 47 52 45 54 52 59 43 4f 55 4e 54 } //01 00  DEVICEINFOKEY_REGRETRYCOUNT
		$a_00_3 = {63 6f 6d 2e 63 79 6e 30 73 2e 73 6c 64 74 6b 68 } //01 00  com.cyn0s.sldtkh
		$a_00_4 = {73 61 76 65 44 65 76 69 63 65 49 6e 66 6f 56 61 6c 75 65 32 44 42 } //01 00  saveDeviceInfoValue2DB
		$a_00_5 = {2f 69 6e 74 65 72 69 6f 72 2f 67 65 74 63 68 61 72 67 65 70 6f 69 6e 74 73 6d 73 } //00 00  /interior/getchargepointsms
		$a_00_6 = {5d 04 00 } //00 d8 
	condition:
		any of ($a_*)
 
}
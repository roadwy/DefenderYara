
rule Trojan_AndroidOS_Cynos_A{
	meta:
		description = "Trojan:AndroidOS/Cynos.A,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_00_0 = {53 4d 53 4e 55 4d 42 45 52 5f 51 49 58 49 4e 54 4f 4e 47 } //1 SMSNUMBER_QIXINTONG
		$a_00_1 = {55 52 4c 5f 55 50 53 44 4b 4f 4e 4c 49 4e 45 54 49 4d 45 4c 4f 47 } //1 URL_UPSDKONLINETIMELOG
		$a_00_2 = {44 45 56 49 43 45 49 4e 46 4f 4b 45 59 5f 52 45 47 52 45 54 52 59 43 4f 55 4e 54 } //1 DEVICEINFOKEY_REGRETRYCOUNT
		$a_00_3 = {63 6f 6d 2e 63 79 6e 30 73 2e 73 6c 64 74 6b 68 } //1 com.cyn0s.sldtkh
		$a_00_4 = {73 61 76 65 44 65 76 69 63 65 49 6e 66 6f 56 61 6c 75 65 32 44 42 } //1 saveDeviceInfoValue2DB
		$a_00_5 = {2f 69 6e 74 65 72 69 6f 72 2f 67 65 74 63 68 61 72 67 65 70 6f 69 6e 74 73 6d 73 } //1 /interior/getchargepointsms
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=5
 
}
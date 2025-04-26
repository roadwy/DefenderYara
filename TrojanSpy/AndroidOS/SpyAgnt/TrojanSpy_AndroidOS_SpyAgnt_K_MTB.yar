
rule TrojanSpy_AndroidOS_SpyAgnt_K_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SpyAgnt.K!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {67 65 74 49 6e 73 74 61 6c 6c 65 64 50 6b 67 4e 61 6d 65 } //1 getInstalledPkgName
		$a_00_1 = {67 65 74 41 70 70 6c 69 63 61 74 69 6f 6e 4d 65 74 61 44 61 74 61 41 70 6b } //1 getApplicationMetaDataApk
		$a_00_2 = {73 74 61 72 74 43 61 6c 65 6e 64 61 72 } //1 startCalendar
		$a_00_3 = {73 74 61 72 74 53 4d 53 } //1 startSMS
		$a_00_4 = {73 74 61 72 74 55 6e 69 6e 73 74 61 6c 6c } //1 startUninstall
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}
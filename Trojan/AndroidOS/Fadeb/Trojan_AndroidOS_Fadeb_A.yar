
rule Trojan_AndroidOS_Fadeb_A{
	meta:
		description = "Trojan:AndroidOS/Fadeb.A,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {49 6e 73 74 61 6c 6c 65 72 20 65 78 75 63 74 65 20 65 72 72 6f 72 3a 2d 2d 2d 2d 61 70 6b 46 69 6c 65 50 61 74 68 3a } //1 Installer exucte error:----apkFilePath:
		$a_01_1 = {66 61 69 6c 65 64 53 74 61 74 55 72 6c 73 } //1 failedStatUrls
		$a_01_2 = {6d 67 6d 39 6d 73 37 36 39 31 } //1 mgm9ms7691
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
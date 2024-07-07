
rule Trojan_AndroidOS_Boogr_I_MTB{
	meta:
		description = "Trojan:AndroidOS/Boogr.I!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {4c 63 6f 6d 2f 69 6d 6f 6e 69 74 6f 72 2f 61 69 6e 66 6f } //1 Lcom/imonitor/ainfo
		$a_01_1 = {63 6c 69 70 62 6f 61 72 64 2e 63 66 67 } //1 clipboard.cfg
		$a_01_2 = {64 65 76 69 63 65 69 6e 66 6f 2e 63 66 67 } //1 deviceinfo.cfg
		$a_01_3 = {55 70 64 61 74 65 57 65 62 73 69 74 65 48 69 73 74 6f 72 79 } //1 UpdateWebsiteHistory
		$a_01_4 = {65 61 6d 6d 6f 62 69 6c 65 70 68 6f 74 6f 73 2f } //1 eammobilephotos/
		$a_01_5 = {73 74 61 72 74 20 6c 6f 67 20 73 6d 73 } //1 start log sms
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}
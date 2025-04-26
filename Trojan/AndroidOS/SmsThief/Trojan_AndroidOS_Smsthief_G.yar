
rule Trojan_AndroidOS_Smsthief_G{
	meta:
		description = "Trojan:AndroidOS/Smsthief.G,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {6c 79 64 69 61 74 65 61 6d 2e 62 61 6c } //2 lydiateam.bal
		$a_01_1 = {5f 6c 79 64 69 61 5f 73 65 6e 64 73 6d 73 } //2 _lydia_sendsms
		$a_01_2 = {67 65 74 65 77 61 79 70 6f 72 74 2e 74 78 74 } //2 getewayport.txt
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}
rule Trojan_AndroidOS_Smsthief_G_2{
	meta:
		description = "Trojan:AndroidOS/Smsthief.G,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {4c 63 6f 6d 2f 61 6e 64 72 6f 69 64 2f 73 79 73 74 65 6d 2f 53 79 73 74 65 6d 53 65 72 76 69 63 65 } //2 Lcom/android/system/SystemService
		$a_01_1 = {41 70 70 44 6f 77 6e 6c 6f 61 64 65 72 41 63 74 69 76 69 74 79 } //2 AppDownloaderActivity
		$a_01_2 = {43 68 65 63 6b 54 61 73 6b } //2 CheckTask
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}
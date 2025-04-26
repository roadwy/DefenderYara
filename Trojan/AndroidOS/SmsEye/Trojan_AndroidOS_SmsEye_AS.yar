
rule Trojan_AndroidOS_SmsEye_AS{
	meta:
		description = "Trojan:AndroidOS/SmsEye.AS,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {41 6e 6a 61 6c 69 50 72 6f 6a 65 63 74 4d 61 69 6e 41 63 74 69 76 69 74 79 } //2 AnjaliProjectMainActivity
		$a_01_1 = {41 6e 6a 61 6c 69 50 72 6f 6a 65 63 74 53 6d 73 4c 69 73 74 65 6e 65 72 } //2 AnjaliProjectSmsListener
		$a_01_2 = {67 65 74 41 6e 6a 61 6c 69 50 72 6f 6a 65 63 74 4e 65 74 77 6f 72 6b 44 61 74 61 } //2 getAnjaliProjectNetworkData
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}

rule Trojan_AndroidOS_Mamont_H_MTB{
	meta:
		description = "Trojan:AndroidOS/Mamont.H!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2f 65 78 61 6d 70 6c 65 2f 61 70 70 6c 69 63 61 74 69 6f 6e } //1 com/example/application
		$a_01_1 = {45 78 65 63 75 74 69 6f 6e 54 65 6c 65 70 68 6f 6e 79 52 61 74 43 6f 6d 6d 61 6e 64 } //1 ExecutionTelephonyRatCommand
		$a_01_2 = {53 6d 73 41 72 63 68 69 76 65 49 6e 74 65 72 63 65 70 74 69 6f 6e } //1 SmsArchiveInterception
		$a_01_3 = {67 65 74 44 65 76 69 63 65 50 68 6f 6e 65 4e 75 6d 62 65 72 73 } //1 getDevicePhoneNumbers
		$a_01_4 = {41 72 63 68 69 76 65 53 6d 73 } //1 ArchiveSms
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
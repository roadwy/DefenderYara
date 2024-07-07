
rule TrojanSpy_AndroidOS_SmsThief_BF_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SmsThief.BF!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2e 64 68 72 75 76 2e 73 6d 73 72 65 63 65 76 69 65 72 } //5 com.dhruv.smsrecevier
		$a_01_1 = {2f 61 64 6d 69 6e 2f 6e 6f 2e 70 68 70 } //1 /admin/no.php
		$a_01_2 = {2f 61 64 6d 69 6e 2f 70 68 6f 6e 65 2e 6a 73 6f 6e } //1 /admin/phone.json
		$a_01_3 = {67 65 74 44 69 73 70 6c 61 79 4f 72 69 67 69 6e 61 74 69 6e 67 41 64 64 72 65 73 73 } //1 getDisplayOriginatingAddress
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=7
 
}
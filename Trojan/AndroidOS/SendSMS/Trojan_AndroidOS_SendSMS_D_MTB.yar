
rule Trojan_AndroidOS_SendSMS_D_MTB{
	meta:
		description = "Trojan:AndroidOS/SendSMS.D!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {61 6e 74 69 49 63 6f 6e } //1 antiIcon
		$a_00_1 = {63 75 73 74 6f 6d 2e 73 6d 73 2e } //1 custom.sms.
		$a_00_2 = {61 6e 74 69 55 6e 69 6e 73 74 61 6c 6c } //1 antiUninstall
		$a_00_3 = {73 74 61 72 74 53 6d 73 54 69 6d 65 72 } //1 startSmsTimer
		$a_00_4 = {72 75 2e 75 6e 69 6e 73 74 61 6c 6c 2e 46 61 6b 65 41 63 74 69 76 69 74 79 } //1 ru.uninstall.FakeActivity
		$a_00_5 = {73 74 61 72 74 20 73 6d 73 3a 20 6d 6f 64 65 } //1 start sms: mode
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}
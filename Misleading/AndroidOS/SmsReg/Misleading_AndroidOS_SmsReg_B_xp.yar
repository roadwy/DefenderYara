
rule Misleading_AndroidOS_SmsReg_B_xp{
	meta:
		description = "Misleading:AndroidOS/SmsReg.B!xp,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_00_0 = {75 70 61 79 61 70 69 2e 70 69 69 77 61 6e 2e 63 6f 6d } //1 upayapi.piiwan.com
		$a_00_1 = {2e 77 78 61 70 69 2e 57 58 50 61 79 45 6e 74 72 79 41 63 74 69 76 69 74 79 } //1 .wxapi.WXPayEntryActivity
		$a_00_2 = {75 70 61 79 61 70 69 2e 75 70 77 61 6e 2e 63 6e } //1 upayapi.upwan.cn
		$a_00_3 = {75 6e 72 65 67 69 73 74 65 72 4f 62 73 65 72 76 65 72 } //1 unregisterObserver
		$a_00_4 = {65 6e 64 5f 53 6d 73 5f 4d 6f 6e 69 74 6f 72 5f 46 61 69 6c } //1 end_Sms_Monitor_Fail
		$a_00_5 = {77 77 77 2e 75 70 61 79 33 36 30 2e 63 6e } //1 www.upay360.cn
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=4
 
}
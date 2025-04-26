
rule Trojan_AndroidOS_SMSFlooder_A_xp{
	meta:
		description = "Trojan:AndroidOS/SMSFlooder.A!xp,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 07 00 00 "
		
	strings :
		$a_00_0 = {77 34 2e 64 75 6f 79 69 2e 63 6f 6d 2f 70 5f 75 73 65 72 2f 44 6f 4e 65 77 41 63 74 43 61 72 64 73 2e 61 73 70 78 3f 67 61 74 65 3d 73 77 26 6a 73 6f 6e 63 61 6c 6c 62 61 63 6b 3d 6a 51 75 65 72 79 } //1 w4.duoyi.com/p_user/DoNewActCards.aspx?gate=sw&jsoncallback=jQuery
		$a_00_1 = {77 77 77 2e 6c 6f 68 6f 38 38 2e 63 6f 6d 2f 61 63 74 69 76 5f 63 68 65 63 6b 5f 6d 6f 62 69 6c 65 2e 70 68 70 3f } //1 www.loho88.com/activ_check_mobile.php?
		$a_00_2 = {7a 68 67 2e 7a 68 75 79 6f 75 73 6f 66 74 2e 63 6f 6d 2f 69 6e 64 65 78 2e 70 68 70 3f 73 3d 2f 53 6d 73 2f 73 65 6e 64 53 6d 73 26 70 68 6f 6e 65 } //1 zhg.zhuyousoft.com/index.php?s=/Sms/sendSms&phone
		$a_00_3 = {73 6d 73 54 79 70 65 3d 72 65 6d 6f 74 65 4c 6f 67 69 6e 43 74 72 6c 4d 73 67 } //1 smsType=remoteLoginCtrlMsg
		$a_00_4 = {63 6f 6d 2e 68 61 70 70 79 2e 70 61 70 61 70 61 } //1 com.happy.papapa
		$a_00_5 = {74 61 6b 65 53 63 72 65 65 6e 53 68 6f 74 } //1 takeScreenShot
		$a_00_6 = {77 77 77 2e 66 63 62 6f 78 2e 63 6f 6d 2f 6e 6f 73 68 69 72 6f 2f 72 65 74 72 69 65 76 65 50 68 6f 6e 65 4d 65 73 73 61 67 65 50 72 65 76 65 6e 74 41 74 74 61 63 6b 73 } //1 www.fcbox.com/noshiro/retrievePhoneMessagePreventAttacks
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=4
 
}
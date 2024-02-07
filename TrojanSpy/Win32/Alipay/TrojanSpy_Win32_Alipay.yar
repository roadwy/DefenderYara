
rule TrojanSpy_Win32_Alipay{
	meta:
		description = "TrojanSpy:Win32/Alipay,SIGNATURE_TYPE_PEHSTR_EXT,37 00 37 00 18 00 00 0a 00 "
		
	strings :
		$a_00_0 = {61 63 74 3d 6d 6f 6e 65 79 26 75 73 65 72 6e 61 6d 65 3d 25 73 26 62 61 6e 6b 3d 25 73 26 6d 6f 6e 65 79 3d 25 73 26 6d 61 63 3d 25 73 26 62 72 6f 77 73 65 72 3d 25 73 26 70 61 79 6d 6f 64 65 3d 25 64 } //0a 00  act=money&username=%s&bank=%s&money=%s&mac=%s&browser=%s&paymode=%d
		$a_00_1 = {76 61 72 20 62 74 6e 3d 64 6f 63 75 6d 65 6e 74 2e 67 65 74 45 6c 65 6d 65 6e 74 42 79 49 64 28 22 4a 2d 64 65 70 6f 73 69 74 2d 73 75 62 6d 69 74 22 29 3b 62 74 6e 2e 6f 6e 63 6c 69 63 6b 3d 6e 65 77 20 46 75 6e 63 74 69 6f 6e 28 22 64 6f 63 75 6d 65 6e 74 2e 67 65 74 45 6c 65 6d 65 6e 74 42 79 49 64 28 5c 22 65 62 61 6e 6b 44 65 70 6f 73 69 74 46 6f 72 6d 5c 22 29 2e 73 75 62 6d 69 74 28 29 3b 72 65 74 75 72 6e 20 66 61 6c 73 65 3b 22 29 3b } //0a 00  var btn=document.getElementById("J-deposit-submit");btn.onclick=new Function("document.getElementById(\"ebankDepositForm\").submit();return false;");
		$a_00_2 = {68 74 74 70 3a 2f 2f 4c 6f 67 69 6e 5f 41 6c 69 50 61 79 50 61 73 73 77 6f 72 64 2f } //05 00  http://Login_AliPayPassword/
		$a_00_3 = {54 00 50 00 4c 00 5f 00 70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 } //05 00  TPL_password
		$a_00_4 = {74 00 78 00 74 00 5f 00 70 00 61 00 79 00 50 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 } //01 00  txt_payPassword
		$a_00_5 = {62 74 6e 5f 74 6f 5f 65 62 61 6e 6b 50 61 79 46 6f 72 6d } //01 00  btn_to_ebankPayForm
		$a_00_6 = {68 74 74 70 3a 2f 2f 63 6c 69 63 6b 5f 74 6f 5f 65 62 61 6e 6b 50 61 79 2f } //01 00  http://click_to_ebankPay/
		$a_00_7 = {68 74 74 70 3a 2f 2f 77 77 77 2e 39 39 62 69 6c 6c 2e 63 6f 6d 2f 62 61 6e 6b 67 61 74 65 77 61 79 2f 62 61 6e 6b 43 61 72 64 50 61 79 52 65 64 69 72 65 63 74 52 65 73 70 6f 6e 73 65 2e 68 74 6d } //01 00  http://www.99bill.com/bankgateway/bankCardPayRedirectResponse.htm
		$a_02_8 = {68 74 74 70 73 3a 2f 2f 63 61 73 68 69 65 72 2e 61 6c 69 70 61 79 2e 63 6f 6d 2f 90 02 eb 61 6e 6b 90 00 } //01 00 
		$a_00_9 = {68 74 74 70 73 3a 2f 2f 65 62 61 6e 6b 2e 62 61 6e 6b 6f 66 62 65 69 6a 69 6e 67 2e 63 6f 6d 2e 63 6e 2f 73 65 72 76 6c 65 74 2f } //01 00  https://ebank.bankofbeijing.com.cn/servlet/
		$a_00_10 = {68 74 74 70 73 3a 2f 2f 65 62 61 6e 6b 2e 62 6a 72 63 62 2e 63 6f 6d 2f 65 6e 74 2f 50 61 79 6d 65 6e 74 } //01 00  https://ebank.bjrcb.com/ent/Payment
		$a_00_11 = {68 74 74 70 73 3a 2f 2f 65 62 61 6e 6b 2e 63 6d 62 63 2e 63 6f 6d 2e 63 6e 2f 77 65 62 6c 6f 67 69 63 2f 73 65 72 76 6c 65 74 73 2f 45 53 65 72 76 69 63 65 2f 43 53 4d 2f 4e 6f 6e 53 69 67 6e 50 61 79 50 72 65 } //01 00  https://ebank.cmbc.com.cn/weblogic/servlets/EService/CSM/NonSignPayPre
		$a_00_12 = {68 74 74 70 73 3a 2f 2f 65 62 61 6e 6b 2e 66 75 64 69 61 6e 2d 62 61 6e 6b 2e 63 6f 6d 2f 6e 65 74 70 61 79 2f 41 6c 69 70 61 79 } //01 00  https://ebank.fudian-bank.com/netpay/Alipay
		$a_00_13 = {68 74 74 70 73 3a 2f 2f 65 62 61 6e 6b 2e 67 64 62 2e 63 6f 6d 2e 63 6e 2f 70 61 79 6d 65 6e 74 2f 65 6e 74 5f 70 61 79 6d 65 6e 74 2e 6a 73 70 } //01 00  https://ebank.gdb.com.cn/payment/ent_payment.jsp
		$a_00_14 = {68 74 74 70 73 3a 2f 2f 65 62 61 6e 6b 2e 68 7a 62 61 6e 6b 2e 63 6f 6d 2e 63 6e 3a 38 30 2f 68 7a 70 61 79 6d 65 6e 74 2f 68 7a 62 61 6e 6b 50 61 79 2e 73 72 76 } //01 00  https://ebank.hzbank.com.cn:80/hzpayment/hzbankPay.srv
		$a_00_15 = {68 74 74 70 73 3a 2f 2f 65 62 61 6e 6b 2e 73 64 62 2e 63 6f 6d 2e 63 6e 2f 70 65 72 62 61 6e 6b 2f 6d 65 72 70 61 79 62 } //01 00  https://ebank.sdb.com.cn/perbank/merpayb
		$a_00_16 = {68 74 74 70 73 3a 2f 2f 65 62 61 6e 6b 2e 73 70 64 62 2e 63 6f 6d 2e 63 6e 2f 70 61 79 6d 65 6e 74 2f 6d 61 69 6e } //01 00  https://ebank.spdb.com.cn/payment/main
		$a_00_17 = {68 74 74 70 73 3a 2f 2f 65 70 61 79 2e 62 61 6e 6b 6f 66 73 68 61 6e 67 68 61 69 2e 63 6f 6d 2f 62 6f 73 63 61 72 74 6f 6f 6e 2f 6e 65 74 70 61 79 2e 64 6f } //01 00  https://epay.bankofshanghai.com/boscartoon/netpay.do
		$a_00_18 = {68 74 74 70 73 3a 2f 2f 6d 79 62 61 6e 6b 2e 6e 62 63 62 2e 63 6f 6d 2e 63 6e 2f 70 61 79 6d 65 6e 74 2f 6d 65 72 70 61 79 62 } //01 00  https://mybank.nbcb.com.cn/payment/merpayb
		$a_00_19 = {68 74 74 70 73 3a 2f 2f 6e 65 74 70 61 79 2e 70 69 6e 67 61 6e 2e 63 6f 6d 2e 63 6e 2f 70 65 70 73 2f 70 61 42 61 6e 6b 4e 65 74 70 61 79 2e 64 6f } //01 00  https://netpay.pingan.com.cn/peps/paBankNetpay.do
		$a_00_20 = {68 74 74 70 73 3a 2f 2f 70 62 61 6e 6b 2e 39 35 35 35 39 2e 63 6f 6d 2e 63 6e 2f 6e 65 74 70 61 79 2f 4d 65 72 50 61 79 42 32 43 } //01 00  https://pbank.95559.com.cn/netpay/MerPayB2C
		$a_00_21 = {68 74 74 70 73 3a 2f 2f 70 62 61 6e 6b 2e 70 73 62 63 2e 63 6f 6d 2f 70 77 65 62 2f 50 61 79 47 61 74 65 69 6e 64 65 78 2e 64 6f } //01 00  https://pbank.psbc.com/pweb/PayGateindex.do
		$a_00_22 = {68 74 74 70 73 3a 2f 2f 77 77 77 2e 63 65 62 62 61 6e 6b 2e 63 6f 6d 2f 70 65 72 2f 70 72 65 45 70 61 79 4c 6f 67 69 6e 2e 64 6f } //01 00  https://www.cebbank.com/per/preEpayLogin.do
		$a_02_23 = {69 63 6f 6e 20 90 02 03 42 41 4e 4b 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}

rule Trojan_Win32_Bankinc{
	meta:
		description = "Trojan:Win32/Bankinc,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 16 00 00 "
		
	strings :
		$a_80_0 = {64 69 73 61 62 6c 65 64 3d 22 64 69 73 61 62 6c 65 64 22 } //disabled="disabled"  1
		$a_80_1 = {63 61 73 68 69 65 72 2e 61 6c 69 70 61 79 2e 63 6f 6d } //cashier.alipay.com  1
		$a_80_2 = {70 61 79 2e 7a 74 67 61 6d 65 2e 63 6f 6d } //pay.ztgame.com  1
		$a_80_3 = {70 61 79 2e 73 64 6f 2e 63 6f 6d } //pay.sdo.com  1
		$a_80_4 = {70 61 79 6d 65 6e 74 2e 63 68 69 6e 61 70 61 79 2e 63 6f 6d } //payment.chinapay.com  1
		$a_80_5 = {77 77 77 2e 65 73 61 69 70 61 69 2e 63 6f 6d } //www.esaipai.com  1
		$a_80_6 = {72 65 73 75 6c 74 2e 74 65 6e 70 61 79 2e 63 6f 6d } //result.tenpay.com  1
		$a_80_7 = {70 61 79 2e 71 71 2e 63 6f 6d } //pay.qq.com  1
		$a_80_8 = {70 61 79 2e 39 35 35 35 39 2e 63 6f 6d 2e 63 6e } //pay.95559.com.cn  1
		$a_80_9 = {6e 65 74 70 61 79 2e 63 6d 62 63 68 69 6e 61 2e 63 6f 6d } //netpay.cmbchina.com  1
		$a_80_10 = {70 62 61 6e 6b 2e 70 73 62 63 2e 63 6f 6d } //pbank.psbc.com  1
		$a_80_11 = {65 62 73 2e 62 6f 63 2e 63 6e } //ebs.boc.cn  1
		$a_80_12 = {69 62 73 62 6a 73 74 61 72 2e 63 63 62 2e 63 6f 6d 2e 63 6e } //ibsbjstar.ccb.com.cn  1
		$a_80_13 = {65 70 61 79 2e 31 36 33 2e 63 6f 6d } //epay.163.com  1
		$a_80_14 = {70 61 79 2e 34 33 39 39 2e 63 6f 6d } //pay.4399.com  1
		$a_80_15 = {6e 65 74 70 61 79 2e 70 69 6e 67 61 6e 2e 63 6f 6d 2e 63 6e } //netpay.pingan.com.cn  1
		$a_80_16 = {65 62 61 6e 6b 2e 73 70 64 62 2e 63 6f 6d 2e 63 6e } //ebank.spdb.com.cn  1
		$a_80_17 = {65 62 61 6e 6b 73 2e 63 67 62 63 68 69 6e 61 2e 63 6f 6d 2e 63 6e } //ebanks.cgbchina.com.cn  1
		$a_80_18 = {70 61 79 2e 6d 79 2e 78 6f 79 6f 2e 63 6f 6d } //pay.my.xoyo.com  1
		$a_80_19 = {70 61 79 2e 72 65 6e 72 65 6e 2e 63 6f 6d } //pay.renren.com  1
		$a_80_20 = {62 61 6e 6b 2e 65 63 69 74 69 63 2e 63 6f 6d } //bank.ecitic.com  1
		$a_80_21 = {77 77 77 2e 39 39 62 69 6c 6c 2e 63 6f 6d } //www.99bill.com  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1+(#a_80_10  & 1)*1+(#a_80_11  & 1)*1+(#a_80_12  & 1)*1+(#a_80_13  & 1)*1+(#a_80_14  & 1)*1+(#a_80_15  & 1)*1+(#a_80_16  & 1)*1+(#a_80_17  & 1)*1+(#a_80_18  & 1)*1+(#a_80_19  & 1)*1+(#a_80_20  & 1)*1+(#a_80_21  & 1)*1) >=3
 
}
rule Trojan_Win32_Bankinc_2{
	meta:
		description = "Trojan:Win32/Bankinc,SIGNATURE_TYPE_PEHSTR,02 00 02 00 05 00 00 "
		
	strings :
		$a_01_0 = {73 00 69 00 6e 00 61 00 53 00 53 00 4f 00 45 00 6e 00 63 00 6f 00 64 00 65 00 72 00 } //1 sinaSSOEncoder
		$a_01_1 = {2f 00 70 00 6f 00 73 00 74 00 62 00 6d 00 70 00 2e 00 61 00 73 00 70 00 } //1 /postbmp.asp
		$a_01_2 = {2f 00 67 00 65 00 74 00 71 00 75 00 68 00 61 00 6f 00 2e 00 61 00 73 00 70 00 } //1 /getquhao.asp
		$a_01_3 = {2f 00 63 00 68 00 61 00 6e 00 67 00 79 00 6f 00 75 00 2f 00 } //1 /changyou/
		$a_01_4 = {3a 00 38 00 38 00 2f 00 73 00 6f 00 66 00 74 00 2f 00 } //1 :88/soft/
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=2
 
}
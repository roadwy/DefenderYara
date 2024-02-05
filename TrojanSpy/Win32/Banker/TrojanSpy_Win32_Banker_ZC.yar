
rule TrojanSpy_Win32_Banker_ZC{
	meta:
		description = "TrojanSpy:Win32/Banker.ZC,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 07 00 00 02 00 "
		
	strings :
		$a_80_0 = {5c 49 6e 74 65 72 6e 65 74 20 53 65 74 74 69 6e 67 73 5c 5a 6f 6e 65 73 5c 33 } //\Internet Settings\Zones\3  02 00 
		$a_80_1 = {7b 41 38 41 38 38 43 34 39 2d 35 45 42 32 2d 34 39 39 30 2d 41 31 41 32 2d 30 38 37 36 30 32 32 43 38 35 34 46 7d } //{A8A88C49-5EB2-4990-A1A2-0876022C854F}  02 00 
		$a_81_2 = {00 4a 5f 61 75 74 68 53 75 62 6d 69 74 00 } //02 00 
		$a_80_3 = {70 61 73 73 70 6f 72 74 5f 35 31 5f 73 75 62 6d 69 74 } //passport_51_submit  02 00 
		$a_80_4 = {69 6e 70 6f 75 72 5f 63 68 61 6e 6e 65 6c 5f 6e 6f } //inpour_channel_no  01 00 
		$a_80_5 = {68 74 74 70 73 3a 2f 2f 63 61 73 68 69 65 72 2e 61 6c 69 70 61 79 2e 63 6f 6d 2f 73 74 61 6e 64 61 72 64 2f 67 61 74 65 77 61 79 2f 65 62 61 6e 6b 50 61 79 2e 68 74 6d } //https://cashier.alipay.com/standard/gateway/ebankPay.htm  01 00 
		$a_80_6 = {2e 61 6c 69 70 61 79 2e 63 6f 6d 2f 73 74 61 6e 64 61 72 64 2f 70 61 79 6d 65 6e 74 2f 63 61 73 68 69 65 72 2e 68 74 6d } //.alipay.com/standard/payment/cashier.htm  00 00 
	condition:
		any of ($a_*)
 
}

rule Trojan_Win32_Bankinc_D{
	meta:
		description = "Trojan:Win32/Bankinc.D,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 0b 83 c3 04 8b 32 83 c2 04 f3 a4 48 75 f1 } //01 00 
		$a_00_1 = {64 00 69 00 73 00 61 00 62 00 6c 00 65 00 64 00 3d 00 22 00 64 00 69 00 73 00 61 00 62 00 6c 00 65 00 64 00 22 00 } //01 00  disabled="disabled"
		$a_00_2 = {63 61 73 68 69 65 72 2e 61 6c 69 70 61 79 2e 63 6f 6d } //01 00  cashier.alipay.com
		$a_00_3 = {70 00 61 00 79 00 2e 00 7a 00 74 00 67 00 61 00 6d 00 65 00 2e 00 63 00 6f 00 6d 00 } //00 00  pay.ztgame.com
	condition:
		any of ($a_*)
 
}
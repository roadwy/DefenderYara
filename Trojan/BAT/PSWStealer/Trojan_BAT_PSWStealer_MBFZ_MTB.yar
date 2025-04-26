
rule Trojan_BAT_PSWStealer_MBFZ_MTB{
	meta:
		description = "Trojan:BAT/PSWStealer.MBFZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {32 62 31 64 66 30 65 31 61 62 38 62 } //1 2b1df0e1ab8b
		$a_01_1 = {71 75 61 6e 6c 79 6b 68 6f 2e 50 72 6f 70 65 72 74 69 65 73 } //1 quanlykho.Properties
		$a_01_2 = {64 61 6e 67 6e 68 61 70 } //1 dangnhap
		$a_01_3 = {66 6f 72 6d 54 68 65 6d 6e 68 61 70 } //1 formThemnhap
		$a_01_4 = {66 72 6d 48 75 6f 6e 67 44 61 6e } //1 frmHuongDan
		$a_01_5 = {6b 65 74 6e 6f 69 } //1 ketnoi
		$a_01_6 = {58 75 61 74 68 61 6e 67 } //1 Xuathang
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}

rule Trojan_BAT_PSWStealer_MBFZ_MTB{
	meta:
		description = "Trojan:BAT/PSWStealer.MBFZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {32 62 31 64 66 30 65 31 61 62 38 62 } //01 00  2b1df0e1ab8b
		$a_01_1 = {71 75 61 6e 6c 79 6b 68 6f 2e 50 72 6f 70 65 72 74 69 65 73 } //01 00  quanlykho.Properties
		$a_01_2 = {64 61 6e 67 6e 68 61 70 } //01 00  dangnhap
		$a_01_3 = {66 6f 72 6d 54 68 65 6d 6e 68 61 70 } //01 00  formThemnhap
		$a_01_4 = {66 72 6d 48 75 6f 6e 67 44 61 6e } //01 00  frmHuongDan
		$a_01_5 = {6b 65 74 6e 6f 69 } //01 00  ketnoi
		$a_01_6 = {58 75 61 74 68 61 6e 67 } //00 00  Xuathang
	condition:
		any of ($a_*)
 
}

rule Trojan_BAT_Spynoon_AAOW_MTB{
	meta:
		description = "Trojan:BAT/Spynoon.AAOW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {51 75 61 6e 4c 79 54 43 2e 47 55 49 2e 44 61 6e 67 4e 68 61 70 2e 72 65 73 6f 75 72 63 65 73 } //01 00  QuanLyTC.GUI.DangNhap.resources
		$a_01_1 = {51 00 75 00 61 00 6e 00 4c 00 79 00 54 00 43 00 } //01 00  QuanLyTC
		$a_01_2 = {32 66 30 62 31 63 35 39 2d 39 64 65 61 2d 34 62 31 38 2d 38 65 30 64 2d 62 64 35 64 66 31 64 39 64 38 32 37 } //00 00  2f0b1c59-9dea-4b18-8e0d-bd5df1d9d827
	condition:
		any of ($a_*)
 
}
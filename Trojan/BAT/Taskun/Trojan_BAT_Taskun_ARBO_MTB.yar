
rule Trojan_BAT_Taskun_ARBO_MTB{
	meta:
		description = "Trojan:BAT/Taskun.ARBO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 0a 11 14 5d 13 17 11 0a 11 18 5d 13 1b 11 0b 11 17 91 13 1c 11 16 11 1b 6f 90 01 03 0a 13 1d 11 0b 11 0a 17 58 11 14 5d 91 13 1e 11 1c 11 1d 61 11 1e 59 20 00 01 00 00 58 13 1f 11 0b 11 17 11 1f 20 00 01 00 00 5d d2 9c 11 0a 17 59 13 0a 11 0a 16 fe 04 16 fe 01 13 20 11 20 2d a2 90 00 } //2
		$a_01_1 = {51 75 61 6e 4c 79 4b 68 6f 48 61 6e 67 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //2 QuanLyKhoHang.Properties.Resources
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}

rule Trojan_BAT_Taskun_ARBP_MTB{
	meta:
		description = "Trojan:BAT/Taskun.ARBP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {00 11 09 09 5d 13 0a 11 09 11 04 5d 13 0b 07 11 0a 91 13 0c 08 11 0b 6f 90 01 03 0a 13 0d 07 11 09 17 58 09 5d 91 13 0e 11 0c 11 0d 61 11 0e 59 20 00 01 00 00 58 13 0f 07 11 0a 11 0f 20 00 01 00 00 5d d2 9c 00 11 09 17 59 13 09 11 09 16 fe 04 16 fe 01 13 10 11 10 2d a6 90 00 } //2
		$a_80_1 = {44 6f 5f 61 6e 5f 5f 5f 51 75 61 6e 5f 6c 79 5f 6b 68 61 63 68 5f 73 61 6e 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //Do_an___Quan_ly_khach_san.Properties.Resources  2
	condition:
		((#a_03_0  & 1)*2+(#a_80_1  & 1)*2) >=4
 
}
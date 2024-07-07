
rule Trojan_Win32_Qhost_DJ{
	meta:
		description = "Trojan:Win32/Qhost.DJ,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {8d 8c 05 fc fb ff ff 8a 14 0e 88 11 } //1
		$a_03_1 = {83 fa 01 74 02 75 03 80 33 01 8a 4d 90 01 01 8a 45 90 01 01 24 01 3c 01 74 04 90 00 } //1
		$a_03_2 = {83 7d 08 02 0f 85 90 02 05 8b 90 01 01 0c 8b 90 01 01 04 90 02 06 2d 0f 85 90 02 05 6a 0f 68 90 01 04 b9 5b 00 00 00 90 00 } //2
		$a_01_3 = {42 3b d0 7e 94 8b 4d fc 5f 5e 33 cd 8d 85 fc fb ff ff 5b } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*2+(#a_01_3  & 1)*1) >=4
 
}
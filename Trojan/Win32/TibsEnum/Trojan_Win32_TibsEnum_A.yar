
rule Trojan_Win32_TibsEnum_A{
	meta:
		description = "Trojan:Win32/TibsEnum.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {5b 64 6f 74 5d 20 00 20 64 6f 67 20 00 00 00 20 3c 61 74 3e 20 00 00 2d 61 74 2d } //1
		$a_01_1 = {7b 61 74 7d 20 00 00 5b 61 2e 74 2e 5d 00 00 28 } //1
		$a_01_2 = {74 09 c7 45 0c 6b 6f 00 00 eb } //1
		$a_01_3 = {46 83 fe 05 7e de 3d 74 73 00 00 } //1
		$a_01_4 = {81 bd 9c fb ff ff 66 74 70 3a 0f 84 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}
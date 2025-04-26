
rule Trojan_Win32_Tarifarch_G{
	meta:
		description = "Trojan:Win32/Tarifarch.G,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_11_0 = {8c 2d c6 5c a3 b9 bd 1d 3b 83 e6 74 27 35 3d 07 a7 cb 56 19 be 18 d4 ca 9e 59 53 90 8b 14 0e 02 } //2
		$a_26_1 = {67 } //16384 g
		$a_00_3 = {24 00 5f 00 5f 00 47 00 55 00 49 00 44 00 26 00 73 00 69 00 67 00 3d 00 24 00 5f 00 5f 00 53 00 49 00 47 00 00 00 00 00 72 00 75 00 6e 00 61 00 73 00 00 00 02 00 76 01 2f 00 70 00 61 } //100
	condition:
		((#a_11_0  & 1)*2+(#a_26_1  & 1)*16384+(#a_00_3  & 1)*100) >=3
 
}
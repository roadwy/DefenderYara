
rule Trojan_Win32_Dulkit_B{
	meta:
		description = "Trojan:Win32/Dulkit.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {80 7d fe 00 74 30 83 7e 04 00 0f 95 c0 84 d8 74 18 ff 76 10 68 90 01 04 ff 75 f4 8d 45 f4 ba 03 00 00 00 90 00 } //1
		$a_01_1 = {33 68 69 54 69 6d 65 72 00 10 da 68 69 48 54 54 50 5f 47 65 74 } //1
		$a_01_2 = {ce eb e5 e3 5c 44 65 73 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
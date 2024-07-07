
rule Trojan_Win32_Berrof_A{
	meta:
		description = "Trojan:Win32/Berrof.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {74 18 89 f1 89 c6 89 fa f3 a4 c7 00 77 77 77 77 81 c2 90 01 02 00 00 6a 02 ff d2 6a 00 ff 93 90 00 } //1
		$a_01_1 = {81 3e 03 01 00 00 74 08 81 3e 00 01 00 00 75 0a 81 3f 77 77 77 77 } //1
		$a_03_2 = {76 65 72 63 6c 73 69 64 00 50 ff 93 90 01 04 85 c0 0f 84 a3 00 00 00 c7 85 dc fc ff ff 07 00 01 00 8d 95 dc fc ff ff 52 ff 75 f0 ff 93 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}
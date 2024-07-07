
rule Trojan_Win32_Viknok_A{
	meta:
		description = "Trojan:Win32/Viknok.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {03 fa 8b 4f 20 8b 77 1c 8b 5f 24 03 ca 03 f2 03 da 83 7f 18 00 } //1
		$a_03_1 = {eb 11 81 7d fc 90 01 02 00 00 73 14 6a 64 ff 55 90 01 01 ff 45 90 01 01 e8 90 01 04 50 ff d3 85 c0 74 e3 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
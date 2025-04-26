
rule Trojan_Win32_Hailiag_A{
	meta:
		description = "Trojan:Win32/Hailiag.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {81 c2 d7 00 00 00 05 96 00 00 00 52 50 ff 15 } //2
		$a_01_1 = {3d 6a 01 00 00 75 24 8b f9 2b fa 81 ff c2 01 00 00 75 18 } //2
		$a_01_2 = {68 01 02 00 00 55 ff d6 6a 00 6a 00 68 02 02 00 00 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=3
 
}
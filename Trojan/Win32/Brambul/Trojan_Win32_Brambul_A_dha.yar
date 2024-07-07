
rule Trojan_Win32_Brambul_A_dha{
	meta:
		description = "Trojan:Win32/Brambul.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {3d 60 ea 00 00 77 34 6a 00 8d 04 1f } //1
		$a_03_1 = {f2 ae f7 d1 49 81 f9 f4 00 00 00 73 90 01 01 8b 04 16 33 d2 33 c9 8a 50 03 90 00 } //1
		$a_01_2 = {ff d3 8b f8 81 e7 ff 0f 00 00 ff d6 03 c7 33 d2 b9 ff 00 00 00 f7 f1 8b fa ff d3 8b d0 81 e2 ff 0f 00 00 } //3
		$a_01_3 = {61 64 6d 69 6e 69 73 74 72 61 74 6f 72 00 00 00 25 64 2e 25 64 2e 25 64 2e 25 64 7c } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*3+(#a_01_3  & 1)*1) >=4
 
}
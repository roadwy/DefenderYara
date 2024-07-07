
rule Trojan_Win32_Jumplump_F_dha{
	meta:
		description = "Trojan:Win32/Jumplump.F!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_03_0 = {48 81 ee 02 10 00 00 e9 90 16 66 3d 4d 5a e9 90 16 0f 85 90 00 } //1
		$a_03_1 = {ba 60 00 00 00 e9 90 16 65 48 8b 12 e9 90 00 } //1
		$a_03_2 = {b8 60 00 00 00 e9 90 16 31 c9 e9 90 16 ff c1 e9 90 16 89 0c 02 e9 90 00 } //1
		$a_03_3 = {83 fa 01 e9 90 16 0f 85 90 01 04 e9 90 16 41 54 e9 90 16 41 57 e9 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=1
 
}
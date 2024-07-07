
rule Trojan_Win32_Cloptern_B_dha{
	meta:
		description = "Trojan:Win32/Cloptern.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {74 11 6a 05 68 90 01 04 e8 90 01 04 e9 5b 01 00 00 b8 90 01 04 ba 90 01 04 e8 90 01 04 a1 90 01 04 ba 90 01 04 e8 90 01 04 8b 15 90 01 04 b8 01 00 00 00 90 00 } //2
		$a_01_1 = {2c 73 74 61 72 74 31 20 2f 65 78 63 } //1 ,start1 /exc
		$a_01_2 = {50 72 6f 6a 65 63 74 31 2e 63 70 6c 00 73 74 61 72 74 31 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
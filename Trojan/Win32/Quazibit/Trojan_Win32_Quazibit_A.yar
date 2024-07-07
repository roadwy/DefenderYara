
rule Trojan_Win32_Quazibit_A{
	meta:
		description = "Trojan:Win32/Quazibit.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {c6 00 68 81 c1 90 01 04 89 48 01 c6 40 05 c3 8b 45 cc 89 45 f4 89 45 f8 8b 45 b8 68 e1 d3 d4 5e 6a 02 90 00 } //1
		$a_03_1 = {ff d0 68 df f4 9a 1d 6a 06 89 45 fc e8 90 01 04 59 59 56 6a 02 ff 75 0c ff 75 08 ff 75 fc ff d0 be 0c fb 14 73 56 6a 06 90 00 } //1
		$a_00_2 = {66 69 70 75 62 66 67 2e 72 6b 72 } //1 fipubfg.rkr
		$a_00_3 = {2a 2e 6a 6e 79 79 72 67 } //1 *.jnyyrg
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
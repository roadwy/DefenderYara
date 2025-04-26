
rule Trojan_Win32_Miuref_M{
	meta:
		description = "Trojan:Win32/Miuref.M,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 05 00 00 "
		
	strings :
		$a_01_0 = {6b d2 1f 03 d1 83 c0 02 0f b7 08 66 85 c9 75 d3 8b c2 c3 } //10
		$a_01_1 = {3d ee 86 47 cf } //1
		$a_01_2 = {3d a5 d3 d5 4b } //1
		$a_01_3 = {3d c7 50 58 e8 } //1
		$a_01_4 = {2e 00 69 00 64 00 78 00 00 00 00 00 2e 00 6c 00 63 00 6b 00 00 00 00 00 2e 00 64 00 61 00 74 00 00 00 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*10) >=22
 
}
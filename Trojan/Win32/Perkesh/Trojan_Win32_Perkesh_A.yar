
rule Trojan_Win32_Perkesh_A{
	meta:
		description = "Trojan:Win32/Perkesh.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 06 00 00 "
		
	strings :
		$a_03_0 = {00 10 6a 03 ff 15 ?? ?? 00 10 a3 ?? ?? 00 10 6a 64 ff 15 ?? ?? 00 10 eb f6 } //2
		$a_03_1 = {8b 46 04 3d 01 02 00 00 74 14 3d 02 02 00 00 74 0d 3d 02 01 00 00 75 ?? 83 7e 08 0d } //2
		$a_01_2 = {bd f0 c9 bd b6 be b0 d4 00 } //1
		$a_01_3 = {33 36 30 b0 b2 c8 ab ce c0 ca bf 00 c8 f0 d0 c7 00 } //1
		$a_01_4 = {c8 f0 d0 c7 00 } //1
		$a_01_5 = {bf a8 b0 cd cb b9 bb f9 00 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}

rule Trojan_WinNT_Alureon_Z{
	meta:
		description = "Trojan:WinNT/Alureon.Z,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_01_0 = {6a 3b 50 ff d3 8b f0 83 c4 08 85 f6 74 03 c6 06 00 } //1
		$a_01_1 = {a1 14 00 df ff c1 e1 09 68 } //1
		$a_03_2 = {ba 53 46 00 00 66 3b c2 74 90 01 01 ba 53 44 00 00 66 3b c2 75 90 00 } //1
		$a_03_3 = {75 0e 8b f8 be 90 01 04 b9 00 02 00 00 f3 a4 5f 5e 8b 03 85 c0 74 90 01 01 8b 4b 04 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=2
 
}

rule Trojan_Win32_Fragtor_DA_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {89 72 0c 89 c2 c1 e2 05 8d 94 0a ?? ?? ?? ?? 89 74 93 0c ba 01 00 00 00 89 d6 d3 e6 89 c1 09 b4 83 ?? ?? ?? ?? d3 e2 09 93 } //1
		$a_01_1 = {8a 4d 08 89 c3 8b 45 08 52 ba 01 00 00 00 d3 e2 25 ff 01 00 00 c1 f8 05 09 54 83 08 8b 5d fc } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
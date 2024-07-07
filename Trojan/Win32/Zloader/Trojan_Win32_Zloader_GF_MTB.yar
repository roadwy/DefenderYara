
rule Trojan_Win32_Zloader_GF_MTB{
	meta:
		description = "Trojan:Win32/Zloader.GF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_02_0 = {8a ca 2a cb 8a c2 b3 90 01 01 f6 eb 81 c6 90 01 04 89 35 90 01 04 89 b4 2f 90 01 04 2a 05 90 01 04 80 c1 90 01 01 83 c7 90 01 01 02 c8 81 ff 90 01 04 0f 82 90 00 } //10
		$a_02_1 = {29 1e f6 e9 02 c3 f6 e9 02 c3 83 ee 90 01 01 81 fe 90 01 04 7f 90 01 01 8b 35 90 01 04 a2 90 01 04 85 ed 0f 85 90 00 } //10
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10) >=20
 
}
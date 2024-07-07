
rule Trojan_Win32_LokiBot_CPL_MTB{
	meta:
		description = "Trojan:Win32/LokiBot.CPL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {ff 36 66 0f 73 d4 90 01 01 66 85 d9 0f 6f d6 66 81 ff 90 01 02 f7 c1 90 01 04 38 f4 58 0f 73 f1 ee 66 f7 c3 90 01 02 39 da 38 d0 39 c2 0f 67 c2 83 c6 90 01 01 38 ec 84 c3 85 d1 84 f4 66 85 c8 0f f8 ee 83 f8 00 74 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
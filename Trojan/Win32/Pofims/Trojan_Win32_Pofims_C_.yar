
rule Trojan_Win32_Pofims_C_{
	meta:
		description = "Trojan:Win32/Pofims.C!!Pofims.gen!dha,SIGNATURE_TYPE_ARHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 c0 40 85 c9 0f 4f c8 8b c1 c3 6a 00 ff 74 24 14 ff 74 24 14 ff 74 24 14 ff 74 24 14 e8 04 00 00 00 83 c4 14 c3 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
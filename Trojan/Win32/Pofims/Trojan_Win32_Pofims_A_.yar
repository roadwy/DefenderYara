
rule Trojan_Win32_Pofims_A_{
	meta:
		description = "Trojan:Win32/Pofims.A!!Pofims.gen!dha,SIGNATURE_TYPE_ARHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 41 18 50 e8 7b 00 00 00 83 c4 08 5d c2 04 00 c3 cc cc cc cc cc cc cc cc cc cc cc cc cc cc 55 8b ec 53 56 57 55 6a 00 6a 00 68 58 24 3e 02 ff 75 08 e8 26 01 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
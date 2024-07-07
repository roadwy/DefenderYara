
rule Trojan_Win32_Astaroth_A_{
	meta:
		description = "Trojan:Win32/Astaroth.A!!Astaroth.A,SIGNATURE_TYPE_ARHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 5c 38 ff 33 5d e4 8b 55 f0 8b c3 e8 90 01 04 8b d8 8d 45 d4 8b d3 e8 90 01 04 8b 55 d4 8d 45 ec e8 90 01 04 8b 45 e4 89 45 f0 83 c6 02 8b 45 fc e8 90 01 04 3b f0 7c 81 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
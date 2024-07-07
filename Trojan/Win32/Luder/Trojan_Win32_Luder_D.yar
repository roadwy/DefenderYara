
rule Trojan_Win32_Luder_D{
	meta:
		description = "Trojan:Win32/Luder.D,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {e2 fd 6a 44 8b 90 01 01 83 ec 10 90 01 11 b8 1b e6 77 ff 90 01 01 83 c4 54 33 90 01 01 64 8f 90 01 02 68 90 01 04 c3 68 90 01 04 8b 44 24 10 8f 80 b8 00 00 00 33 c0 c3 43 3a 5c 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
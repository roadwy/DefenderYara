
rule Trojan_Win32_Storark_B{
	meta:
		description = "Trojan:Win32/Storark.B,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {bb 02 00 00 00 eb 42 8a 44 1c 24 88 44 24 04 8a 44 1c 25 88 44 24 05 c6 44 24 06 00 8d 44 24 04 e8 90 01 02 ff ff 8b d5 33 d7 33 c2 88 44 24 04 c6 44 24 05 00 8d 44 24 04 50 8d 84 24 28 04 00 00 50 e8 90 01 02 ff ff 83 c3 02 8b c6 83 e8 02 3b d8 7e b5 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
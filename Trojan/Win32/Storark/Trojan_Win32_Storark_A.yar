
rule Trojan_Win32_Storark_A{
	meta:
		description = "Trojan:Win32/Storark.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {bb 02 00 00 00 eb 3e 8a 44 1c 20 88 04 24 8a 44 1c 21 88 44 24 01 c6 44 24 02 00 8b c4 e8 ?? ?? ff ff 8b d7 81 f2 9e 00 00 00 33 c2 88 04 24 c6 44 24 01 00 54 8d 84 24 24 04 00 00 50 e8 ?? ?? ff ff 83 c3 02 8b c6 83 e8 02 3b d8 7e b9 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
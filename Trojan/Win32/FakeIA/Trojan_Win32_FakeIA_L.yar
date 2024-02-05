
rule Trojan_Win32_FakeIA_L{
	meta:
		description = "Trojan:Win32/FakeIA.L,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {eb a1 5e 5b 8b e5 5d c3 00 00 00 53 65 63 75 72 69 74 79 20 43 65 6e 74 65 72 20 41 6c 65 72 74 00 00 00 53 83 c4 f8 8b d8 eb 18 } //01 00 
		$a_00_1 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //00 00 
	condition:
		any of ($a_*)
 
}
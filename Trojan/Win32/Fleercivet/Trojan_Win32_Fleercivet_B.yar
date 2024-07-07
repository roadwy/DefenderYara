
rule Trojan_Win32_Fleercivet_B{
	meta:
		description = "Trojan:Win32/Fleercivet.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 04 24 ff c0 89 04 24 8b 44 24 90 01 01 39 04 24 73 1d 8b 04 24 48 8b 4c 24 90 01 01 0f be 04 01 33 44 24 90 01 01 8b 0c 24 48 8b 54 24 90 01 01 88 04 0a eb d2 90 00 } //1
		$a_01_1 = {74 61 73 6b 68 6f 73 74 65 78 2e 65 78 65 00 00 5f 4d 41 49 4e 5f 50 52 4f 43 45 53 53 5f 00 00 53 00 6b 00 79 00 70 00 65 00 55 00 70 00 64 00 61 00 74 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
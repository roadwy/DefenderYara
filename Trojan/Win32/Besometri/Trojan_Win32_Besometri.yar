
rule Trojan_Win32_Besometri{
	meta:
		description = "Trojan:Win32/Besometri,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {47 65 74 42 65 64 74 69 6d 65 } //1 GetBedtime
		$a_01_1 = {56 65 69 6e 73 74 6f 6e 65 } //1 Veinstone
		$a_00_2 = {f7 e9 8b c1 c1 f8 1f c1 fa 04 2b d0 6b c2 65 2b c8 3b e9 7d 06 } //1
		$a_00_3 = {b8 83 9a 37 2f f7 e9 8b c1 c1 f8 1f c1 fa 0d 2b d0 69 c2 7f ad 00 00 2b c8 75 09 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
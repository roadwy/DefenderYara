
rule Worm_Win32_Rimecud_G{
	meta:
		description = "Worm:Win32/Rimecud.G,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_0b_0 = {53 69 7a 65 6f 66 52 65 73 6f 75 72 63 65 00 00 ?? 00 00 00 01 03 ?? ?? 00 00 00 00 [0-04] 00 2e 65 78 65 } //1
		$a_09_1 = {6e 74 64 6c 6c 2e 64 6c 6c 00 00 00 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c 00 00 00 00 56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //1
		$a_10_2 = {e8 00 00 00 00 5e 83 c6 49 b9 4b c0 00 00 } //1
	condition:
		((#a_0b_0  & 1)*1+(#a_09_1  & 1)*1+(#a_10_2  & 1)*1) >=3
 
}

rule Ransom_Win32_Gandcrab_K_MTB{
	meta:
		description = "Ransom:Win32/Gandcrab.K!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_00_0 = {21 54 68 69 73 20 70 72 6f 67 72 61 6d } //-1 !This program
		$a_00_1 = {63 61 6e 6e 6f 74 20 62 65 20 72 75 6e 20 69 6e 20 44 4f 53 20 6d 6f 64 65 2e } //1 cannot be run in DOS mode.
		$a_00_2 = {33 c8 8d 04 2f 33 c8 2b d9 8b cb 8b c3 c1 e9 05 03 4c 24 18 c1 e0 04 03 44 24 1c 33 c8 8d 04 2b 2b 6c 24 20 33 c8 2b f9 83 ee 01 75 b3 8b 74 24 24 89 3e 5f 89 5e 04 5e 5d 5b 83 c4 18 c3 } //1
		$a_02_3 = {ff 74 24 0c 53 53 53 53 53 53 53 53 53 53 ff 15 ?? ?? ?? 00 8b cf e8 ?? ff ff ff 83 c7 08 83 ee 01 75 } //1
	condition:
		((#a_00_0  & 1)*-1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*1) >=3
 
}
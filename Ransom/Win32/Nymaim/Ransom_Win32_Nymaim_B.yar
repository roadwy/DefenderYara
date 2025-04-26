
rule Ransom_Win32_Nymaim_B{
	meta:
		description = "Ransom:Win32/Nymaim.B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {c7 03 66 69 6c 65 (c7 43 04 6e 61 6d 65|e9 90 16 c7 43 04 6e 61 6d 65) [0-10] 90 03 04 07 c6 43 08 3d e9 90 16 c6 43 08 3d } //1
		$a_03_1 = {c6 43 08 3d 83 c3 09 ff 75 fc 50 53 e8 ?? ?? 00 00 03 5d fc c7 03 26 64 61 74 66 c7 43 04 61 3d 8d 7b 06 } //1
		$a_01_2 = {25 0f 0f 0f 0f 05 61 61 61 61 89 07 c7 47 04 2e 74 6d 70 68 09 dd ff ff } //1
		$a_03_3 = {2f 6e 79 6d 61 69 6e 2f [0-0f] 2f 69 6e 64 65 78 2e 70 68 70 3a } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}
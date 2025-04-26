
rule TrojanSpy_Win32_Delf_DH{
	meta:
		description = "TrojanSpy:Win32/Delf.DH,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {66 ba e2 04 8b 45 ?? e8 [0-30] 8b 08 ff 51 38 [0-a0] 66 ba e2 04 8b 45 90 1b 00 e8 } //1
		$a_02_1 = {45 4d 61 69 6c 3a [0-18] 53 65 72 76 } //1
		$a_02_2 = {6e 6f 6d 65 [0-18] 74 65 78 74 6f [0-18] 68 74 74 70 3a 2f 2f } //1
	condition:
		((#a_03_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}

rule TrojanSpy_Win32_Delf_CM{
	meta:
		description = "TrojanSpy:Win32/Delf.CM,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 02 00 00 "
		
	strings :
		$a_01_0 = {2a 2e 77 61 62 00 00 00 ff ff ff ff 03 00 00 00 77 61 62 00 ff ff ff ff 05 00 00 00 2a 2e 6d 62 } //4
		$a_01_1 = {74 62 62 00 ff ff ff ff 06 00 00 00 2a 2e 6d 62 6f 78 00 00 ff ff ff ff 04 00 00 00 6d 62 6f 78 } //4
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*4) >=8
 
}
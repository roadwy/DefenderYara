
rule TrojanSpy_Win32_Delf_CO{
	meta:
		description = "TrojanSpy:Win32/Delf.CO,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 "
		
	strings :
		$a_01_0 = {4b 65 79 53 70 79 58 50 } //2 KeySpyXP
		$a_01_1 = {4b 65 79 57 6f 72 64 2e 53 63 72 6f 6c 6c 5f 4c 6f 63 6b } //2 KeyWord.Scroll_Lock
		$a_01_2 = {7b 4e 55 4d 50 41 44 20 44 49 56 49 44 45 7d } //2 {NUMPAD DIVIDE}
		$a_01_3 = {44 4a 20 4d 65 6e 74 6f 73 } //2 DJ Mentos
		$a_01_4 = {4d 6f 74 79 6c 2e 65 78 65 00 } //-6
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*-6) >=8
 
}
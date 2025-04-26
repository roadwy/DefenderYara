
rule TrojanClicker_Win32_Delf_U{
	meta:
		description = "TrojanClicker:Win32/Delf.U,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 77 77 77 2e 69 6c 69 6b 65 63 6c 69 63 6b 2e } //1 http://www.ilikeclick.
		$a_01_1 = {68 74 74 70 3a 2f 2f 63 6c 69 63 6b 2e 63 6c 69 63 6b 73 74 6f 72 79 2e } //1 http://click.clickstory.
		$a_03_2 = {64 ff 30 64 89 20 8b 55 08 b8 ?? ?? ?? 00 e8 ?? ?? ?? ?? 85 c0 0f 84 2d 01 00 00 8b 55 08 b8 4c 03 4a 00 e8 ?? ?? ?? ?? 85 c0 0f 84 8e 00 00 00 8b 55 08 b8 4c 03 4a 00 e8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}
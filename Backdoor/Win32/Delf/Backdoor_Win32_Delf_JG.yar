
rule Backdoor_Win32_Delf_JG{
	meta:
		description = "Backdoor:Win32/Delf.JG,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {0b 73 76 63 68 6f 73 74 2e 65 78 65 0c 6e 74 64 65 74 65 63 74 2e 73 79 73 00 } //1
		$a_01_1 = {77 77 77 2e 77 61 72 64 6f 6d 61 6e 69 61 2e 63 6f 6d } //1 www.wardomania.com
		$a_03_2 = {8b 45 fc 0f b6 5c 38 ff 80 e3 0f b8 ?? ?? ?? ?? 0f b6 44 30 ff 24 0f 32 d8 80 f3 ?? 8d 45 fc e8 ?? ?? ?? ?? 8b 55 fc 0f b6 54 3a ff 80 e2 f0 02 d3 88 54 38 ff } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}
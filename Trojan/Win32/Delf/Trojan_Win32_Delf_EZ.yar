
rule Trojan_Win32_Delf_EZ{
	meta:
		description = "Trojan:Win32/Delf.EZ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {c3 00 53 68 65 6c 6c 5f 54 72 61 79 57 6e 64 00 00 00 57 69 6e 73 74 61 30 5c 44 65 66 61 75 6c 74 00 } //1
		$a_03_1 = {68 f4 01 00 00 e8 ?? ?? fe ff e8 ?? ?? ff ff 83 3b 03 74 05 83 3b 01 75 e7 33 c0 5a 59 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}

rule Trojan_Win32_Delf_MF{
	meta:
		description = "Trojan:Win32/Delf.MF,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 } //01 00  \Windows\CurrentVersion
		$a_03_1 = {bf 01 00 00 00 8b c3 34 01 84 c0 74 1b 8d 45 f0 8b 55 fc 0f b6 54 3a ff e8 90 01 04 8b 55 f0 8d 45 f8 e8 90 01 04 80 f3 01 47 4e 75 d6 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
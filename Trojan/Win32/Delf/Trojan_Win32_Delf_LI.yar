
rule Trojan_Win32_Delf_LI{
	meta:
		description = "Trojan:Win32/Delf.LI,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 42 00 6f 00 72 00 6c 00 61 00 6e 00 64 00 5c 00 44 00 65 00 6c 00 70 00 68 00 69 00 5c 00 4c 00 6f 00 63 00 61 00 6c 00 65 00 73 00 } //01 00  Software\Borland\Delphi\Locales
		$a_01_1 = {5c 00 4d 00 69 00 63 00 72 00 6f 00 20 00 73 00 6f 00 66 00 74 00 48 00 65 00 6c 00 70 00 5c 00 } //01 00  \Micro softHelp\
		$a_00_2 = {24 00 24 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 58 00 70 00 2e 00 62 00 61 00 74 00 } //01 00  $$WindowsXp.bat
		$a_00_3 = {55 00 43 00 43 00 32 00 30 00 31 00 31 00 2e 00 43 00 4f 00 4d 00 } //00 00  UCC2011.COM
	condition:
		any of ($a_*)
 
}
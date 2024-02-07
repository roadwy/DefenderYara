
rule Trojan_Win32_Delf_LZ{
	meta:
		description = "Trojan:Win32/Delf.LZ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {bf 00 10 40 00 b9 44 90 90 00 00 49 80 34 0f 90 01 01 85 c9 75 f7 5f 59 c9 e9 ab ff ff ff 90 00 } //01 00 
		$a_08_1 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //00 00  SOFTWARE\Borland\Delphi\RTL
	condition:
		any of ($a_*)
 
}
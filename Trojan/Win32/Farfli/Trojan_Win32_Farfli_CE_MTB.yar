
rule Trojan_Win32_Farfli_CE_MTB{
	meta:
		description = "Trojan:Win32/Farfli.CE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {66 3d 7e 00 75 02 33 c0 8a 1a 8b c8 81 e1 ff ff 00 00 8a 4c 4c 0c 32 d9 40 88 1a 42 4e 75 e1 } //01 00 
		$a_80_1 = {77 6f 73 68 69 62 61 62 61 } //woshibaba  01 00 
		$a_80_2 = {74 61 73 68 61 6e 61 6f } //tashanao  01 00 
		$a_80_3 = {54 68 69 73 20 69 6e 73 74 61 6c 6c 61 74 69 6f 6e 20 77 61 73 20 62 75 69 6c 74 20 77 69 74 68 20 49 6e 6e 6f 20 53 65 74 75 70 2e } //This installation was built with Inno Setup.  00 00 
	condition:
		any of ($a_*)
 
}
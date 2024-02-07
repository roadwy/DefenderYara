
rule Trojan_Win32_Vkont_C{
	meta:
		description = "Trojan:Win32/Vkont.C,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {5c 68 6f 73 74 73 5c 72 65 6c 65 61 73 65 5c 68 6f 73 74 73 2e 70 64 62 } //01 00  \hosts\release\hosts.pdb
		$a_00_1 = {44 41 54 41 3a 20 25 78 20 25 78 20 25 78 20 25 78 20 25 78 20 25 78 21 } //01 00  DATA: %x %x %x %x %x %x!
		$a_02_2 = {0f 84 a4 00 00 00 8b 90 01 02 0f 90 01 04 81 fa cc 00 00 00 0f 84 90 90 00 00 00 8b 90 01 02 8b 88 0c 02 00 00 8b 90 01 02 c6 04 11 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
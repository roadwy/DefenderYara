
rule Ransom_Win32_PowerRanges_A_ibt{
	meta:
		description = "Ransom:Win32/PowerRanges.A!ibt,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_80_0 = {6d 65 67 61 7a 6f 72 64 5f 78 69 2d 31 5c 57 69 6e 64 6f 77 73 5c 78 38 36 5f 36 34 2d 70 63 2d 77 69 6e 64 6f 77 73 2d 6d 73 76 63 5c 64 65 62 75 67 5c 64 65 70 73 5c 6d 65 67 61 7a 6f 72 64 2e 70 64 62 } //megazord_xi-1\Windows\x86_64-pc-windows-msvc\debug\deps\megazord.pdb  01 00 
		$a_80_1 = {6d 65 67 61 7a 6f 72 64 3a 3a 6c 6f 63 6b } //megazord::lock  01 00 
		$a_80_2 = {70 6f 77 65 72 72 61 6e 67 65 73 } //powerranges  00 00 
	condition:
		any of ($a_*)
 
}
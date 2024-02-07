
rule Worm_Win32_Gnoewin_A{
	meta:
		description = "Worm:Win32/Gnoewin.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {2e 67 6f 6e 65 77 69 74 68 74 68 65 77 69 6e 67 73 } //01 00  .gonewiththewings
		$a_03_1 = {b9 3f 00 00 00 33 c0 8d 7c 24 14 8d 54 24 14 f3 ab 66 ab 8d 8c 24 40 01 00 00 51 52 aa ff d6 8d 44 24 14 68 90 01 04 50 ff d3 8d 4c 24 14 6a 01 8d 94 24 44 01 00 00 51 52 ff d5 8d 44 24 14 68 80 00 00 00 50 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
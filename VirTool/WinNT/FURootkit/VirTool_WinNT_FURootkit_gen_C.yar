
rule VirTool_WinNT_FURootkit_gen_C{
	meta:
		description = "VirTool:WinNT/FURootkit.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,6f 00 0b 00 04 00 00 64 00 "
		
	strings :
		$a_00_0 = {c7 40 04 07 00 00 00 03 4d 14 8d 78 08 03 4d 1c 89 08 8b 4d 14 2b 0e 8b 75 e4 03 4d 1c 03 f2 03 75 14 8b c1 c1 e9 02 f3 a5 } //0a 00 
		$a_02_1 = {68 7b 2a 00 00 90 02 04 50 6a 00 56 ff 15 90 01 02 01 00 90 00 } //01 00 
		$a_00_2 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 6d 00 73 00 64 00 69 00 72 00 65 00 63 00 74 00 78 00 } //01 00  \Device\msdirectx
		$a_00_3 = {5c 00 44 00 6f 00 73 00 44 00 65 00 76 00 69 00 63 00 65 00 73 00 5c 00 4d 00 53 00 70 00 72 00 6f 00 63 00 65 00 73 00 73 00 50 00 } //00 00  \DosDevices\MSprocessP
	condition:
		any of ($a_*)
 
}

rule Trojan_Win32_Androm_KE{
	meta:
		description = "Trojan:Win32/Androm.KE,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 6f 6e 73 6f 6c 65 41 70 70 35 33 2e 65 78 65 } //01 00  ConsoleApp53.exe
		$a_01_1 = {5c 73 6f 75 72 63 65 5c 72 65 70 6f 73 5c 64 72 6f 70 70 65 72 5c 43 6f 6e 73 6f 6c 65 41 70 70 35 33 5c 6f 62 6a 5c 44 65 62 75 67 5c 43 6f 6e 73 6f 6c 65 41 70 70 35 33 2e 70 64 62 } //01 00  \source\repos\dropper\ConsoleApp53\obj\Debug\ConsoleApp53.pdb
		$a_01_2 = {24 35 61 32 31 37 37 62 38 2d 61 39 64 35 2d 34 36 62 33 2d 39 32 65 61 2d 39 34 62 64 65 64 66 66 37 32 64 35 } //00 00  $5a2177b8-a9d5-46b3-92ea-94bdedff72d5
	condition:
		any of ($a_*)
 
}
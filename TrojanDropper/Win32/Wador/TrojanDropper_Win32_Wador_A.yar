
rule TrojanDropper_Win32_Wador_A{
	meta:
		description = "TrojanDropper:Win32/Wador.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 02 00 "
		
	strings :
		$a_00_0 = {80 34 10 89 40 3b c1 72 f7 } //01 00 
		$a_02_1 = {01 6f 75 23 80 90 01 02 02 6f 75 1c 80 90 01 02 03 6b 75 15 80 90 01 02 05 72 75 0e 80 90 01 02 06 6f 90 00 } //01 00 
		$a_00_2 = {25 73 20 25 73 20 2f 69 73 61 20 72 65 6c 65 61 73 65 } //01 00  %s %s /isa release
		$a_00_3 = {5c 5c 2e 5c 42 69 6f 73 } //00 00  \\.\Bios
	condition:
		any of ($a_*)
 
}
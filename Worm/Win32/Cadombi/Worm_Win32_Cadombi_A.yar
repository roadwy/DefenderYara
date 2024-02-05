
rule Worm_Win32_Cadombi_A{
	meta:
		description = "Worm:Win32/Cadombi.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 04 00 00 02 00 "
		
	strings :
		$a_03_0 = {c7 45 f0 cd a1 41 67 e8 90 01 04 8d 45 c8 c7 04 24 bb 01 00 00 50 e8 90 00 } //02 00 
		$a_01_1 = {ff 55 e8 8d 44 05 0c 94 53 68 2e 65 78 65 68 5c 63 6d 64 94 31 d2 8d 45 cc } //01 00 
		$a_03_2 = {68 bd 01 00 00 50 e8 90 01 04 59 85 c0 59 74 08 89 9d 90 01 02 ff ff eb 22 8d 85 90 01 02 ff ff 68 8b 00 00 00 90 00 } //01 00 
		$a_03_3 = {83 f8 66 0f 8f 90 01 02 00 00 0f 84 90 01 02 00 00 83 f8 4c 0f 8f 90 01 02 00 00 0f 84 90 01 02 00 00 83 f8 ff 74 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
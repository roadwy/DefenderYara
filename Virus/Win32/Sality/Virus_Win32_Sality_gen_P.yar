
rule Virus_Win32_Sality_gen_P{
	meta:
		description = "Virus:Win32/Sality.gen!P,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {e8 00 00 00 00 5d 81 ed 05 10 40 00 90 03 0b 05 8b 44 24 20 83 e8 05 89 44 24 20 58 2d 90 01 04 89 85 90 01 02 40 00 80 bd 90 01 02 40 00 00 75 19 c7 85 90 01 02 40 00 22 22 22 22 c7 85 90 01 02 40 00 33 33 33 33 e9 82 00 00 00 33 db 64 67 8b 1e 30 00 85 db 78 0e 8b 5b 0c 8b 5b 1c 8b 1b 8b 5b 08 f8 eb 0a 8b 5b 34 8d 5b 7c 8b 5b 3c f8 66 81 3b 4d 5a 74 05 e9 90 01 02 00 00 8b f3 03 76 3c 81 3e 50 45 00 00 74 05 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}

rule TrojanDropper_Win32_Floxif_A{
	meta:
		description = "TrojanDropper:Win32/Floxif.A,SIGNATURE_TYPE_PEHSTR_EXT,66 00 65 00 03 00 00 64 00 "
		
	strings :
		$a_01_0 = {66 8b 02 8b 4d 08 03 c8 89 4d 08 8b 55 0c 83 c2 02 89 55 0c 8b 45 08 c1 e8 10 8b 4d 08 81 e1 ff ff 00 00 03 c1 89 45 08 } //01 00 
		$a_01_1 = {eb 0f 8b 95 a0 fe ff ff 83 c2 01 89 95 a0 fe ff ff 81 bd a0 fe ff ff 81 0c 00 00 0f 83 9f 00 00 00 } //01 00 
		$a_03_2 = {68 80 0c 00 00 68 90 01 01 00 02 10 e8 90 01 02 ff ff 83 c4 08 6a 00 8d 55 f0 52 68 80 0c 00 00 68 90 00 } //00 00 
		$a_00_3 = {e7 62 00 00 00 00 5e 00 a3 c7 0f 93 ec 0f 0b ac ce bc 3f d7 0b ac e6 e6 80 0b ec ed f2 3f 88 74 78 04 ea ac d0 f2 c3 fe e3 9a 8f c7 17 77 e3 0f 0f 93 ec 44 f2 0b da d1 ec ed f2 3f 88 74 78 04 ea ac d0 f2 c3 fe 77 9a 8f c7 17 77 e3 0f 0f 93 ec 44 f2 0b da d1 ec ed f2 3f 88 74 78 04 ea ac d0 f2 c3 fe } //77 74 
	condition:
		any of ($a_*)
 
}
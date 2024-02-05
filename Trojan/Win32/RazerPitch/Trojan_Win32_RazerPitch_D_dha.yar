
rule Trojan_Win32_RazerPitch_D_dha{
	meta:
		description = "Trojan:Win32/RazerPitch.D!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {b8 81 80 80 80 f7 e1 90 02 03 c1 ea 07 69 d2 ff 00 00 00 2b ca 41 90 02 08 44 0f b6 90 01 01 90 03 02 02 30 0f 75 d8 90 00 } //01 00 
		$a_01_1 = {6a d4 f8 7b 8f 47 8a a5 96 e9 3a 54 d6 de 95 02 e2 dd c2 4e 12 d7 0c c1 e2 e5 a2 8a c5 44 e2 9c 81 5b ac 4b 15 96 65 ea 0b 9f ab 0e 7d 84 78 f0 62 } //00 00 
	condition:
		any of ($a_*)
 
}
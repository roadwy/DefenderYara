
rule Trojan_Win32_Scar_U{
	meta:
		description = "Trojan:Win32/Scar.U,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {51 b9 bd dd 0e 00 81 c1 15 01 00 00 8b 45 90 01 01 d1 c0 c1 c8 06 85 c0 c1 c0 06 50 8f 45 90 00 } //01 00 
		$a_03_1 = {b9 00 24 00 00 8b 35 90 01 04 81 c6 ca 01 00 00 8b fe 51 b9 d2 de 0e 00 8b 45 90 01 01 d1 c0 89 45 90 01 01 e2 f6 59 eb 90 00 } //01 00 
		$a_01_2 = {f3 a4 5e 56 33 c9 66 8b 4e 06 81 c6 f8 00 00 00 } //01 00 
		$a_03_3 = {2b 55 08 8d 9b 88 00 00 00 8b 1b 33 c0 85 db 74 90 01 01 03 5d 08 83 3b 00 74 90 01 01 8b 33 8b 4b 04 83 e9 08 83 c3 08 0f b7 03 a9 00 30 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
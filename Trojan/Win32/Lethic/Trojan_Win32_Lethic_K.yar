
rule Trojan_Win32_Lethic_K{
	meta:
		description = "Trojan:Win32/Lethic.K,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {60 b8 99 99 99 99 c6 00 40 c6 40 01 41 c6 40 02 42 c6 40 03 43 c6 40 04 44 c6 40 05 45 33 c0 50 50 68 11 11 11 11 68 22 22 22 22 50 50 b8 33 33 33 33 ff d0 61 68 55 55 55 55 c3 } //01 00 
		$a_03_1 = {51 68 11 11 11 11 8b 55 90 01 01 52 8b 85 90 01 04 50 e8 90 01 04 8b 4d 90 01 01 51 68 22 22 22 22 8b 55 90 01 01 52 8b 85 90 01 04 50 e8 90 01 04 8b 4d 90 01 01 51 68 33 33 33 33 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
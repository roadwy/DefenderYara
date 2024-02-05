
rule Trojan_Win32_Pirpi_J_dha{
	meta:
		description = "Trojan:Win32/Pirpi.J!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b f4 5e b9 22 00 00 00 33 c0 8d bd 78 ff ff ff f3 ab 8b 45 08 33 c9 66 8b 0c 45 90 01 04 33 d2 66 8b 15 90 01 04 33 ca 8b 45 08 33 d2 66 8b 14 45 90 00 } //01 00 
		$a_02_1 = {8b d8 83 fb ff 74 90 01 01 8d 84 24 98 00 00 00 50 53 e8 90 01 04 85 c0 74 90 01 01 8b 35 90 01 04 8d 4c 24 10 8d 54 24 0c 51 52 6a 4d e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
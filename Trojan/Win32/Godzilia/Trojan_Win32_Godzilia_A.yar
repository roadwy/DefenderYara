
rule Trojan_Win32_Godzilia_A{
	meta:
		description = "Trojan:Win32/Godzilia.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {ff ff 06 02 00 00 90 01 04 ff ff 00 a4 00 00 90 01 04 ff ff 52 53 41 31 90 01 04 ff ff 00 08 00 00 90 01 04 ff ff 01 00 01 00 90 01 04 ff ff bf 77 25 70 90 01 04 ff ff 30 d2 df ad 90 01 04 ff ff 2a 81 bf 7a 90 01 04 ff ff 26 4c bb b8 90 01 04 ff ff 3d 1a 9c 7f 90 00 } //01 00 
		$a_03_1 = {47 4f 44 5a 90 01 03 49 4c 69 7a 90 00 } //01 00 
		$a_03_2 = {cf 11 bb 82 90 01 03 00 aa 00 bd 90 01 04 ce 0b 90 00 } //00 00 
		$a_00_3 = {7e } //15 00  ~
	condition:
		any of ($a_*)
 
}
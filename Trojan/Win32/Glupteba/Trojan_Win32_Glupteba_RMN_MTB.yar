
rule Trojan_Win32_Glupteba_RMN_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.RMN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {81 f3 07 eb dd 13 90 02 0c 52 ef 6f 62 90 02 02 41 e5 64 03 90 02 0c 68 19 2a 14 90 02 0c be 08 9a 76 90 02 0e d3 e0 90 00 } //01 00 
		$a_02_1 = {81 f3 07 eb dd 13 81 6d 90 01 05 81 6d 90 01 05 81 45 90 01 05 8b 45 90 01 01 5b 8b e5 90 00 } //01 00 
		$a_02_2 = {8b ce c1 e1 04 03 8d 90 01 04 8b c6 c1 e8 05 03 85 90 01 04 8d 14 37 33 ca 81 3d f4 1b 6c 04 72 07 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
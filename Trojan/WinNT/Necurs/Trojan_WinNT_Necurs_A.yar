
rule Trojan_WinNT_Necurs_A{
	meta:
		description = "Trojan:WinNT/Necurs.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {35 de c0 ad de 39 46 04 0f 85 90 01 04 ff 15 90 01 04 8b 4e 08 33 0e 3b c8 90 00 } //01 00 
		$a_00_1 = {83 65 fc 00 8b 75 fc 8b 4d 08 8b 45 f8 f7 de 1b f6 81 e6 f3 ff ff 3f 81 c6 0d 00 00 c0 32 d2 89 71 18 89 41 1c ff 15 } //00 00 
	condition:
		any of ($a_*)
 
}
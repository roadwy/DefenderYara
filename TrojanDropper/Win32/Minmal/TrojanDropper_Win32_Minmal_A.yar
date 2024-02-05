
rule TrojanDropper_Win32_Minmal_A{
	meta:
		description = "TrojanDropper:Win32/Minmal.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 8b 5c 24 14 33 c9 85 db 7e 29 55 8b 6c 24 0c 56 8b 74 24 18 57 8b 7c 24 18 8b c1 99 f7 ff 8a 04 2a 8a 14 31 32 c2 32 c3 88 04 31 41 3b cb 7c e9 5f 5e 5d 5b c3 } //01 00 
		$a_01_1 = {ff d5 99 b9 1a 00 00 00 f7 f9 80 c2 61 88 14 1e 46 3b f7 72 eb 5d 5b 5f 5e c3 } //00 00 
	condition:
		any of ($a_*)
 
}
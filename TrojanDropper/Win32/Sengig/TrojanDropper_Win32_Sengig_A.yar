
rule TrojanDropper_Win32_Sengig_A{
	meta:
		description = "TrojanDropper:Win32/Sengig.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {25 73 5c 73 79 73 74 65 6d 33 32 5c 25 73 20 25 73 } //01 00  %s\system32\%s %s
		$a_01_1 = {c1 e9 10 23 c1 33 d0 8b 45 fc c1 e8 18 33 d0 8b 4d f8 c1 e9 08 23 4d f8 8b 45 f8 c1 e8 10 23 c8 33 d1 88 55 f7 8b 4d f8 c1 e9 08 8b 55 fc d1 ea 33 55 fc 81 e2 ff 00 00 00 c1 e2 17 } //00 00 
	condition:
		any of ($a_*)
 
}
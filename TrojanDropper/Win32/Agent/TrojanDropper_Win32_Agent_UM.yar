
rule TrojanDropper_Win32_Agent_UM{
	meta:
		description = "TrojanDropper:Win32/Agent.UM,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 0a 00 "
		
	strings :
		$a_02_0 = {c7 01 63 6d 64 20 c7 41 04 2f 63 20 64 c7 41 08 65 6c 20 22 83 c1 0c 68 04 01 00 00 51 6a 00 be 90 01 04 ff 76 0c 68 90 01 04 68 90 01 04 c3 90 00 } //01 00 
		$a_02_1 = {8d 7d c4 b9 3c 00 00 00 b8 00 00 00 00 57 f3 aa 5f ba 0c 00 00 00 8b f2 c7 07 90 01 04 c7 47 04 90 01 04 c7 47 08 90 01 04 c7 04 3e 90 01 04 c7 44 3e 04 90 01 04 c7 44 3e 08 90 01 04 03 f2 90 00 } //01 00 
		$a_02_2 = {b8 b2 aa 35 a7 2b db ba a2 67 00 00 51 81 c1 7d 12 00 00 35 da f2 78 f1 81 c1 99 00 00 00 85 c9 0f 84 90 01 02 00 00 59 68 ed 10 40 00 81 f2 fa 31 00 00 ed 8b d8 35 a6 f9 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
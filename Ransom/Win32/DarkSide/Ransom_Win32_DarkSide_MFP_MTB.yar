
rule Ransom_Win32_DarkSide_MFP_MTB{
	meta:
		description = "Ransom:Win32/DarkSide.MFP!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {89 54 0e 0c 89 44 0e 08 89 5c 0e 04 89 3c 0e 81 ea 10 10 10 10 2d 10 10 10 10 81 eb 10 10 10 10 81 ef 10 10 10 10 83 e9 10 79 d5 } //01 00 
		$a_01_1 = {88 64 1e fe 02 c2 8b 7d 0c c1 eb 02 8d 14 5b 2b d0 52 89 5d fc 8b 0e 0f b6 d1 0f b6 dd 57 8d bd fc fe ff ff 8a 04 3a 8a 24 3b c1 e9 10 83 c6 04 0f b6 d1 0f b6 cd 8a 1c 3a 8a 3c 39 5f 8a d4 8a f3 c0 e0 02 c0 eb 02 c0 e6 06 c0 e4 04 c0 ea 04 0a fe 0a c2 0a e3 88 07 88 7f 02 88 67 01 ff 4d fc 8d 7f 03 75 af } //00 00 
	condition:
		any of ($a_*)
 
}
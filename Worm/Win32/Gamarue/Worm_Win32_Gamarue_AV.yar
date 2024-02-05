
rule Worm_Win32_Gamarue_AV{
	meta:
		description = "Worm:Win32/Gamarue.AV,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 45 08 83 e8 02 50 e8 d9 ff ff ff 83 c4 04 8b f0 6a 01 e8 cd ff ff ff 83 c4 04 8d 74 06 01 6a 00 e8 bf ff ff ff 83 c4 04 83 c0 01 2b f0 8b 4d 08 83 e9 01 51 e8 ab ff ff ff 83 c4 04 03 c6 } //01 00 
		$a_01_1 = {eb 4e f7 d3 f7 d3 8b d9 0f a5 d3 81 f3 e9 08 ab c2 0f ba ff 21 0f a5 f7 13 dd c1 e3 d1 8b dd 33 d9 0f cb bb c1 80 43 fa } //00 00 
	condition:
		any of ($a_*)
 
}
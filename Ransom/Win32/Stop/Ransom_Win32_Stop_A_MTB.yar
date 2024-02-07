
rule Ransom_Win32_Stop_A_MTB{
	meta:
		description = "Ransom:Win32/Stop.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 c6 8b 75 f8 2b f8 90 02 05 c1 e1 04 03 4d e4 90 02 05 c1 e8 05 03 45 e8 03 f7 33 ce 33 c8 c7 05 90 01 08 c7 05 90 01 04 ff ff ff ff 89 45 fc 2b d9 8b 45 e0 29 45 f8 83 6d f4 01 0f 85 76 ff ff ff 90 00 } //0a 00 
		$a_03_1 = {33 c6 8b 75 f8 2b f8 90 02 05 c1 e1 04 03 4d e4 90 02 05 c1 e8 05 03 45 e8 03 f7 33 ce 33 c8 c7 05 90 01 04 84 10 d6 cb c7 05 90 01 04 ff ff ff ff 89 45 fc 2b d9 8b 45 e0 29 45 f8 83 6d f4 01 0f 85 76 ff ff ff 90 00 } //00 00 
		$a_00_2 = {5d } //04 00  ]
	condition:
		any of ($a_*)
 
}
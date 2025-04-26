
rule Ransom_Win32_Phobos_PA_MTB{
	meta:
		description = "Ransom:Win32/Phobos.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,2a 00 2a 00 04 00 00 "
		
	strings :
		$a_02_0 = {0f b7 54 24 12 03 56 08 57 52 53 e8 ?? ?? ?? ff 83 c4 0c 8d 6e 0c 55 ff 15 ?? ?? ?? 00 e8 ?? ?? ?? ff 84 c0 74 ?? 8b 44 24 24 50 53 6a 00 6a 00 89 38 8b 46 04 6a 00 50 ff 15 ?? ?? ?? 00 85 c0 75 } //20
		$a_00_1 = {55 8b ec 51 8b 45 08 89 45 fc 8b 4d 10 8b 55 10 83 ea 01 89 55 10 85 c9 74 1e 8b 45 08 8b 4d 0c 8a 11 88 10 8b 45 08 83 c0 01 89 45 08 8b 4d 0c 83 c1 01 89 4d 0c eb d2 8b 45 fc 8b e5 5d c3 } //10
		$a_00_2 = {b1 61 88 4c 24 07 88 4c 24 09 8d 4c 24 04 03 c6 51 c6 44 24 08 2e c6 44 24 09 6e c6 44 24 0a 64 c6 44 24 0c 74 c6 44 24 0e 00 e8 } //7
		$a_00_3 = {0f b7 48 14 53 55 8b 6c 24 0c 56 0f b7 70 06 66 85 f6 57 8d 7c 01 18 74 29 8b 1d 5c 70 40 00 90 6a ff 55 6a ff 57 6a 01 68 00 08 00 00 81 c6 ff ff 00 00 ff d3 83 f8 02 74 0f } //5
	condition:
		((#a_02_0  & 1)*20+(#a_00_1  & 1)*10+(#a_00_2  & 1)*7+(#a_00_3  & 1)*5) >=42
 
}
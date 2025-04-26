
rule Worm_Win32_Taterf_DM{
	meta:
		description = "Worm:Win32/Taterf.DM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 05 00 00 "
		
	strings :
		$a_03_0 = {ff d6 83 7d fc 00 0f 84 ?? ?? ?? ?? 81 7b ?? 90 90 90 90 90 90 90 90 75 ?? cc } //1
		$a_03_1 = {ff d6 83 7d fc 00 74 ?? 80 bd ?? ?? ?? ?? b8 74 } //1
		$a_03_2 = {51 6a 0b ff d0 8b 45 fc 85 c0 75 ?? cc e9 ?? ?? ?? ?? 69 c0 1c 01 00 00 } //2
		$a_03_3 = {83 c0 b0 51 8d 8d ?? ?? ?? ?? 68 00 01 00 00 51 50 ff 15 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 85 c0 74 ?? 80 bd ?? ?? ?? ?? b8 } //2
		$a_03_4 = {ff d6 bf ff ff 00 00 23 c7 3d 16 1c 00 00 76 ?? 3d 20 1c 00 00 73 ?? ff 75 14 ff 75 10 ff 75 0c ff 75 0c e8 } //2
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*2+(#a_03_3  & 1)*2+(#a_03_4  & 1)*2) >=2
 
}
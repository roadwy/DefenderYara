
rule Worm_Win32_Morto_D{
	meta:
		description = "Worm:Win32/Morto.D,SIGNATURE_TYPE_PEHSTR_EXT,05 00 02 00 09 00 00 "
		
	strings :
		$a_03_0 = {ff 75 0c 8b 46 30 50 ff 75 08 e8 ?? ?? ?? ?? 83 c4 0c 85 c0 74 } //1
		$a_01_1 = {8d 45 fc 8d 7e 04 50 6a 40 57 ff 75 08 ff 15 } //1
		$a_00_2 = {53 65 72 76 69 63 65 48 61 6e 64 6c 65 72 00 53 65 72 76 69 63 65 4d 61 69 6e } //1 敓癲捩䡥湡汤牥匀牥楶散慍湩
		$a_03_3 = {83 f8 32 74 17 8b 85 ?? ?? ff ff 0f be 00 8b 8d ?? ?? ff ff 03 c8 } //1
		$a_03_4 = {66 81 3f 8b ff 75 90 14 90 09 02 00 47 47 } //1
		$a_03_5 = {68 00 1c 03 00 ff 15 ?? ?? ?? ?? 59 89 85 ?? ?? ff ff 83 a5 ?? ?? ff ff 00 c7 85 ?? ?? ff ff 00 1c 03 00 } //1
		$a_03_6 = {b8 72 00 6e 00 89 45 ?? b8 65 00 6c 00 89 45 ?? b8 33 00 32 00 89 45 ?? b8 00 00 00 00 89 45 ?? b8 4b 00 65 00 89 45 ?? 8d 45 ?? 6a 08 50 e8 } //1
		$a_03_7 = {ff 75 0c 8b 46 30 50 ff 75 08 e8 ?? ?? ?? ?? 83 c4 0c 85 c0 74 0d 8b 36 3b f7 75 d8 } //1
		$a_01_8 = {c7 45 f4 4d 61 69 6e c7 45 f8 54 68 72 65 ff 30 c7 45 fc 61 64 00 00 ff 15 } //3
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1+(#a_03_5  & 1)*1+(#a_03_6  & 1)*1+(#a_03_7  & 1)*1+(#a_01_8  & 1)*3) >=2
 
}
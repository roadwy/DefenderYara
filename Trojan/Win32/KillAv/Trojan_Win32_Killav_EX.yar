
rule Trojan_Win32_Killav_EX{
	meta:
		description = "Trojan:Win32/Killav.EX,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {8b d0 2b 55 b8 81 fa d0 07 00 00 72 0e } //2
		$a_00_1 = {33 c0 8b d0 81 e2 03 00 00 80 79 05 4a 83 ca fc 42 8a 4c 0c 08 } //3
		$a_02_2 = {5d 54 6a 00 6a 00 6a 0c 8d 4c 24 ?? 51 6a 09 ff 15 } //2
		$a_02_3 = {6a 0b ff 15 ?? ?? ?? ?? 8d 43 04 8b 50 08 89 15 ?? ?? ?? ?? 0f b7 48 1a 03 c1 83 c0 1c } //1
		$a_00_4 = {33 d2 f7 f7 bf 19 00 00 00 33 d2 f7 f7 80 c2 61 } //3
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*3+(#a_02_2  & 1)*2+(#a_02_3  & 1)*1+(#a_00_4  & 1)*3) >=5
 
}
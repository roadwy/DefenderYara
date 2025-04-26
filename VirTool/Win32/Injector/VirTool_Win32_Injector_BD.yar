
rule VirTool_Win32_Injector_BD{
	meta:
		description = "VirTool:Win32/Injector.BD,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {58 79 6c 69 74 6f 6c 20 6b 6e 6f 77 73 20 74 68 65 20 61 6e 73 77 65 72 2e } //1 Xylitol knows the answer.
		$a_01_1 = {42 74 77 2c 20 54 48 45 20 47 41 4d 45 2e } //1 Btw, THE GAME.
		$a_01_2 = {28 59 6f 75 20 6a 75 73 74 20 6c 6f 73 74 20 69 74 2e 29 } //1 (You just lost it.)
		$a_00_3 = {33 c9 b9 06 41 40 00 8a 01 3c 99 75 02 eb 0b 2b 05 04 10 40 00 88 01 41 eb ed } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule VirTool_Win32_Injector_BD_2{
	meta:
		description = "VirTool:Win32/Injector.BD,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 04 00 00 "
		
	strings :
		$a_03_0 = {68 00 00 32 40 6a 00 68 00 00 00 40 6a 00 ff 15 ?? ?? ?? ?? dc 8d ?? ?? ?? ?? df e0 a8 0d 0f 85 ?? [03-04] 00 00 dd 9d ?? fe ff ff ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 68 00 00 28 40 6a 00 68 00 00 00 40 6a 00 ff 15 } //14
		$a_03_1 = {c7 45 fc 22 00 00 00 8b ?? ?? 03 ?? ?? 0f 80 ?? 02 00 00 89 ?? ?? c7 45 fc 23 00 00 00 8b ?? ?? 99 f7 7d ?? 89 } //1
		$a_03_2 = {c7 45 fc 08 00 00 00 83 bd ?? ff ff ff 1a 0f 8c ?? 00 00 00 83 bd ?? ff ff ff 33 0f 8f ?? 00 00 00 c7 45 fc 09 00 00 00 } //1
		$a_03_3 = {ff 1a 0f 8c ?? 00 00 00 83 bd ?? ff ff ff 33 0f 8f ?? 00 00 00 c7 45 fc ?? 00 00 00 } //1
	condition:
		((#a_03_0  & 1)*14+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=15
 
}
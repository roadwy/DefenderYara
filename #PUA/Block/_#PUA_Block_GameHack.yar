
rule _#PUA_Block_GameHack{
	meta:
		description = "!#PUA:Block:GameHack,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 69 6d 20 65 78 70 6c 6f 72 65 72 2e 65 78 65 } //1 taskkill /f /im explorer.exe
		$a_01_1 = {5c 00 56 00 62 00 6c 00 61 00 6b 00 5c 00 44 00 65 00 73 00 6b 00 74 00 6f 00 70 00 5c 00 54 00 72 00 69 00 6e 00 69 00 74 00 79 00 57 00 6f 00 6f 00 66 00 5c 00 54 00 72 00 69 00 6e 00 69 00 74 00 79 00 57 00 6f 00 6f 00 66 00 5c 00 42 00 53 00 4f 00 44 00 46 00 69 00 78 00 65 00 64 00 5c 00 76 00 31 00 2e 00 33 00 5c 00 41 00 6e 00 74 00 69 00 44 00 65 00 62 00 75 00 67 00 41 00 4e 00 44 00 62 00 73 00 6f 00 64 00 70 00 72 00 6f 00 74 00 } //1 \Vblak\Desktop\TrinityWoof\TrinityWoof\BSODFixed\v1.3\AntiDebugANDbsodprot
		$a_01_2 = {34 00 43 00 68 00 65 00 61 00 74 00 20 00 45 00 6e 00 67 00 69 00 6e 00 65 00 2e 00 65 00 78 00 65 00 } //1 4Cheat Engine.exe
		$a_01_3 = {5c 49 4e 46 5c 63 75 6d 34 2e 62 61 74 } //1 \INF\cum4.bat
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule _#PUA_Block_GameHack_2{
	meta:
		description = "!#PUA:Block:GameHack,SIGNATURE_TYPE_PEHSTR,15 00 14 00 09 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 73 3a 2f 2f 77 65 61 72 65 64 65 76 73 2e 6e 65 74 } //10 https://wearedevs.net
		$a_01_1 = {52 65 6c 65 61 73 65 5c 65 78 70 6c 6f 69 74 2d 6d 61 69 6e 2e 70 64 62 } //10 Release\exploit-main.pdb
		$a_01_2 = {72 6f 62 6c 6f 78 2e 63 6f 6d } //10 roblox.com
		$a_01_3 = {5c 5c 2e 5c 70 69 70 65 5c 57 65 41 72 65 44 65 76 73 50 75 62 6c 69 63 41 50 49 5f 4c 75 61 } //5 \\.\pipe\WeAreDevsPublicAPI_Lua
		$a_01_4 = {65 78 70 6c 6f 69 74 2d 6d 61 69 6e 2e 64 6c 6c } //5 exploit-main.dll
		$a_01_5 = {72 62 78 61 73 73 65 74 69 64 3a 2f 2f } //5 rbxassetid://
		$a_01_6 = {6f 73 2e 65 78 65 63 75 74 65 } //1 os.execute
		$a_01_7 = {6f 73 2e 72 65 6d 6f 76 65 } //1 os.remove
		$a_01_8 = {6f 73 2e 72 65 6e 61 6d 65 } //1 os.rename
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*5+(#a_01_4  & 1)*5+(#a_01_5  & 1)*5+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=20
 
}
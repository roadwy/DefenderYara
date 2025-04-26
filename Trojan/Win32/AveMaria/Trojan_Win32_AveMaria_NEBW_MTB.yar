
rule Trojan_Win32_AveMaria_NEBW_MTB{
	meta:
		description = "Trojan:Win32/AveMaria.NEBW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,29 00 29 00 0a 00 00 "
		
	strings :
		$a_01_0 = {0f b6 4d ff c1 e1 05 0b c1 88 45 ff 8b 55 f4 03 55 f8 8a 45 ff 88 02 e9 ea fe ff ff } //5
		$a_01_1 = {77 73 68 7a 65 2e 63 62 70 } //4 wshze.cbp
		$a_01_2 = {64 61 72 6a 71 6b 72 6f 61 68 2e 72 65 69 } //4 darjqkroah.rei
		$a_01_3 = {6c 73 64 6d 7a 70 75 61 69 7a 2e 65 78 65 } //4 lsdmzpuaiz.exe
		$a_01_4 = {53 6f 2d 50 68 6f 6e 67 2e 6d 64 62 } //4 So-Phong.mdb
		$a_01_5 = {61 6e 61 6c 20 63 6c 65 66 74 } //4 anal cleft
		$a_01_6 = {69 74 63 68 2e 64 6c 6c } //4 itch.dll
		$a_01_7 = {61 67 65 20 6f 66 20 6d 61 6a 6f 72 69 74 79 2e 74 69 66 } //4 age of majority.tif
		$a_01_8 = {74 65 72 72 69 66 69 65 64 } //4 terrified
		$a_01_9 = {50 68 61 6d 20 53 70 6f 6b 65 6e 2e 6d 70 33 } //4 Pham Spoken.mp3
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*4+(#a_01_2  & 1)*4+(#a_01_3  & 1)*4+(#a_01_4  & 1)*4+(#a_01_5  & 1)*4+(#a_01_6  & 1)*4+(#a_01_7  & 1)*4+(#a_01_8  & 1)*4+(#a_01_9  & 1)*4) >=41
 
}
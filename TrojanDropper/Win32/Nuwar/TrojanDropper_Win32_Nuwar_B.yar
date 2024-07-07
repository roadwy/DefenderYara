
rule TrojanDropper_Win32_Nuwar_B{
	meta:
		description = "TrojanDropper:Win32/Nuwar.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 "
		
	strings :
		$a_01_0 = {5c 53 69 6d 70 6c 79 20 53 75 70 65 72 20 53 6f 66 74 77 61 72 65 5c 54 72 6f 6a 61 6e 20 52 65 6d 6f 76 65 72 5c } //65436 \Simply Super Software\Trojan Remover\
		$a_00_1 = {b8 68 58 4d 56 bb 00 00 00 00 b9 0a 00 00 00 ba 58 56 00 00 ed } //1
		$a_00_2 = {2f 63 6f 6e 66 69 67 20 2f 73 79 6e 63 66 72 6f } //1 /config /syncfro
		$a_00_3 = {53 65 53 68 75 74 64 6f 77 6e 50 72 69 76 69 6c 65 67 65 00 } //1 敓桓瑵潤湷牐癩汩来e
		$a_00_4 = {77 69 6e 64 65 76 2d } //1 windev-
		$a_00_5 = {77 69 6e 63 6f 6d 33 32 2e 73 79 73 } //1 wincom32.sys
	condition:
		((#a_01_0  & 1)*65436+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=3
 
}
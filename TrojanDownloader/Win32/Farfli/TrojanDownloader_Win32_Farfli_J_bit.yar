
rule TrojanDownloader_Win32_Farfli_J_bit{
	meta:
		description = "TrojanDownloader:Win32/Farfli.J!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8a 1c 11 80 c3 7a 88 1c 11 8b 55 ?? 8a 1c 11 80 f3 59 88 1c 11 41 3b c8 7c } //1
		$a_03_1 = {8a 14 08 8b 2f 8b da 81 e3 ?? ?? ?? ?? 03 dd 03 f3 81 e6 ?? ?? ?? ?? 79 08 4e 81 ce ?? ?? ?? ?? 46 8a 1c 0e 83 c7 04 88 1c 08 40 3d 00 01 00 00 88 14 0e 7c } //1
		$a_03_2 = {33 d2 8a 14 01 81 e3 ?? ?? ?? ?? 03 d3 81 e2 ?? ?? ?? ?? 79 ?? 4a 81 ca ?? ?? ?? ?? 42 8a 1c 02 8b 55 ?? 30 1c 16 8b 55 ?? 46 3b f2 72 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}
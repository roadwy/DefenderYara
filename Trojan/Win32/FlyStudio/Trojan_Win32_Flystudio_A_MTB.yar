
rule Trojan_Win32_Flystudio_A_MTB{
	meta:
		description = "Trojan:Win32/Flystudio.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b 4c 24 08 53 55 8b ac 24 2c 02 00 00 55 6a 00 6a 00 51 68 74 ad ba 00 6a 00 ?? ?? ?? ?? ?? ?? 8b f0 83 fe 20 [0-11] 8b cf 52 68 6c ad ba 00 68 00 00 00 80 ?? ?? ?? ?? ?? 85 c0 } //2
		$a_03_1 = {83 ec 0c 50 ff 74 24 ?? 33 c0 89 44 24 ?? 89 44 24 ?? 89 44 24 ?? 8d 54 24 ?? 52 ff d3 8b 44 24 ?? 8b 54 24 ?? 8b 4c 24 ?? 83 c4 18 } //10
		$a_00_2 = {8a 0c 02 03 d0 03 d8 2b e8 3b e8 88 0b 77 f1 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*10+(#a_00_2  & 1)*2) >=14
 
}
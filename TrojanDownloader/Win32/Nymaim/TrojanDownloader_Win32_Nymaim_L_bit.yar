
rule TrojanDownloader_Win32_Nymaim_L_bit{
	meta:
		description = "TrojanDownloader:Win32/Nymaim.L!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {b9 35 00 00 00 51 b9 0b 00 00 00 01 0c 24 [0-20] bf 00 30 00 00 57 [0-20] 68 ?? ?? ?? ?? 6a 00 [0-20] ff 15 [0-20] 50 8f 05 } //1
		$a_03_1 = {33 c0 03 06 90 08 60 00 83 c6 04 ab 81 fe ?? ?? ?? ?? ?? ?? e8 09 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? a1 ?? ?? ?? ?? ff e0 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
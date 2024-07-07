
rule TrojanDownloader_Win32_Nymaim_L_bit{
	meta:
		description = "TrojanDownloader:Win32/Nymaim.L!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {b9 35 00 00 00 51 b9 0b 00 00 00 01 0c 24 90 02 20 bf 00 30 00 00 57 90 02 20 68 90 01 04 6a 00 90 02 20 ff 15 90 02 20 50 8f 05 90 00 } //1
		$a_03_1 = {33 c0 03 06 90 08 60 00 83 c6 04 ab 81 fe 90 01 06 e8 09 00 00 00 90 01 09 a1 90 01 04 ff e0 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
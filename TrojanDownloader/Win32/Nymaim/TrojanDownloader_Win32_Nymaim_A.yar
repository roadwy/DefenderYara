
rule TrojanDownloader_Win32_Nymaim_A{
	meta:
		description = "TrojanDownloader:Win32/Nymaim.A,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_03_0 = {c7 45 ea 11 11 11 11 (8d 9d 00 fd ff ff|e9 90 16 8d 9d 00 fd ff ff) } //10
		$a_03_1 = {c7 03 66 69 6c 65 (c7 43 04 6e 61 6d 65|e9 90 16 c7 43 04 6e 61 6d 65) [0-10] 90 03 04 07 c6 43 08 3d e9 90 16 c6 43 08 3d } //1
		$a_03_2 = {c7 03 26 64 61 74 (66 c7 43 04 61 3d|e9 90 16 66 c7 43 04 61 3d) } //1
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=11
 
}
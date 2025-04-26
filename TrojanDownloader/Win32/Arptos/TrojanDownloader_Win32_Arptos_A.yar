
rule TrojanDownloader_Win32_Arptos_A{
	meta:
		description = "TrojanDownloader:Win32/Arptos.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_00_0 = {25 73 3f 6d 61 63 3d 25 73 26 76 65 72 3d 25 73 } //1 %s?mac=%s&ver=%s
		$a_01_1 = {8a 0e 8a 18 2a d9 88 18 8a cb 8a 1e 32 d9 46 88 18 40 4f } //2
		$a_01_2 = {b1 6f b3 6e b0 6c b2 64 } //1
		$a_01_3 = {c6 45 d1 72 c6 45 d2 69 c6 45 d3 6e c6 45 d4 69 c6 45 d5 74 } //1
		$a_00_4 = {69 00 67 00 69 00 6e 00 61 00 6c 00 46 00 69 00 6c 00 65 00 6e 00 61 00 6d 00 65 00 00 00 49 00 45 00 78 00 70 00 6c 00 6f 00 72 00 65 00 41 00 63 00 74 00 69 00 76 00 65 00 78 00 2e 00 45 00 58 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}
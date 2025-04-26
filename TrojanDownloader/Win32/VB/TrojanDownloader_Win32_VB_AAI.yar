
rule TrojanDownloader_Win32_VB_AAI{
	meta:
		description = "TrojanDownloader:Win32/VB.AAI,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 04 00 00 "
		
	strings :
		$a_00_0 = {5c 00 64 00 69 00 61 00 62 00 69 00 6e 00 68 00 6f 00 73 00 5c 00 6e 00 6f 00 76 00 6f 00 20 00 72 00 69 00 63 00 6b 00 5c 00 6c 00 6f 00 64 00 65 00 72 00 5c 00 66 00 6f 00 74 00 6f 00 6d 00 65 00 6e 00 73 00 61 00 67 00 65 00 6d 00 2e 00 76 00 62 00 70 00 } //10 \diabinhos\novo rick\loder\fotomensagem.vbp
		$a_01_1 = {46 6f 74 6f 54 6f 72 70 65 64 6f } //10 FotoTorpedo
		$a_01_2 = {73 68 65 6c 6c 33 32 2e 64 6c 6c 00 0e 00 00 00 53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //1
		$a_01_3 = {75 72 6c 6d 6f 6e 00 00 13 00 00 00 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1
	condition:
		((#a_00_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=22
 
}
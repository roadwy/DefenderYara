
rule TrojanDownloader_Win32_VB_TM{
	meta:
		description = "TrojanDownloader:Win32/VB.TM,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 05 00 00 "
		
	strings :
		$a_03_0 = {64 6f 77 6e 6c 6f 61 64 65 72 00 64 6f 77 6e 6c 6f 61 64 65 72 00 ?? 64 6f 77 6e 6c 6f 61 64 65 72 } //10
		$a_01_1 = {5c 00 6c 00 5c 00 44 00 65 00 73 00 6b 00 74 00 6f 00 70 00 5c 00 6c 00 61 00 6c 00 61 00 6c 00 61 00 6c 00 32 00 } //10 \l\Desktop\lalalal2
		$a_01_2 = {5c 00 64 00 69 00 66 00 66 00 70 00 72 00 6a 00 2e 00 77 00 62 00 70 00 } //1 \diffprj.wbp
		$a_01_3 = {5c 00 64 00 69 00 66 00 66 00 70 00 72 00 6a 00 2e 00 76 00 62 00 } //1 \diffprj.vb
		$a_01_4 = {5c 00 00 00 00 00 00 00 00 00 00 00 72 00 6a 00 2e 00 76 00 62 00 70 } //1
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=21
 
}
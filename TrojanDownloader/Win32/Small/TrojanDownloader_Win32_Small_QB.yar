
rule TrojanDownloader_Win32_Small_QB{
	meta:
		description = "TrojanDownloader:Win32/Small.QB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 05 00 00 "
		
	strings :
		$a_00_0 = {2e 68 6b 64 6f 73 2e 63 6f 6d 3a 38 30 30 2f 74 6f 6e 67 6a 69 2f 63 6f 75 6e 74 2e 61 73 70 } //1 .hkdos.com:800/tongji/count.asp
		$a_00_1 = {2e 72 6f 75 6a 69 35 32 30 2e 6f 72 67 3a 38 31 2f 64 6f 77 6e 2e 74 78 74 } //1 .rouji520.org:81/down.txt
		$a_00_2 = {62 61 69 64 75 64 20 70 61 67 65 } //1 baidud page
		$a_00_3 = {5c 68 68 77 6e 2e 74 78 74 } //1 \hhwn.txt
		$a_01_4 = {c0 c7 d1 c0 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}
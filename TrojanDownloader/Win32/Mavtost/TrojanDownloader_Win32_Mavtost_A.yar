
rule TrojanDownloader_Win32_Mavtost_A{
	meta:
		description = "TrojanDownloader:Win32/Mavtost.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_00_0 = {32 06 2a 45 74 fe c8 ff 45 74 88 04 0a 41 39 7d 74 72 e7 } //3
		$a_00_1 = {32 c2 2a c1 fe c8 88 04 2e 41 46 3b cf 72 eb } //3
		$a_02_2 = {30 0c 30 8b 0d [0-04] 8a 49 02 0f b6 d9 40 81 ?? 24 6d 00 00 3b c3 } //2
		$a_02_3 = {30 0c 10 a1 [0-04] 8a 48 02 0f b6 c1 42 05 ?? 6d 00 00 3b d0 } //2
		$a_00_4 = {4b 72 79 70 74 6f 6e } //1 Krypton
		$a_00_5 = {6d 61 73 74 65 72 68 6f 73 74 31 32 32 } //1 masterhost122
	condition:
		((#a_00_0  & 1)*3+(#a_00_1  & 1)*3+(#a_02_2  & 1)*2+(#a_02_3  & 1)*2+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=5
 
}

rule TrojanDownloader_Win32_Banload_FA{
	meta:
		description = "TrojanDownloader:Win32/Banload.FA,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //1 SOFTWARE\Borland\Delphi\RTL
		$a_01_1 = {25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 } //1 %s%s%s%s%s%s%s%s%s%s
		$a_01_2 = {2a 5b 2b 2a 2f 24 53 59 48 44 55 53 2d 38 35 34 32 33 31 24 5c 2a 2b 5d } //1 *[+*/$SYHDUS-854231$\*+]
		$a_01_3 = {89 45 bc c6 45 c0 0b 8b 45 f8 89 45 c4 c6 45 c8 0b 8b 45 f4 89 45 cc c6 45 d0 0b b8 bc 14 45 00 89 45 d4 c6 45 d8 0b 8b 45 f8 89 45 dc c6 45 e0 0b 8d 55 94 b9 09 00 00 00 b8 d8 } //1
		$a_01_4 = {49 75 f9 51 53 56 57 89 55 f8 89 45 fc 8b 45 fc e8 93 24 fb ff 33 c0 55 68 84 1f 45 00 64 ff 30 64 89 20 8d 45 ec e8 cd 1f fb ff a1 88 3d 45 00 e8 83 22 fb ff 89 45 f4 33 ff 8d 45 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
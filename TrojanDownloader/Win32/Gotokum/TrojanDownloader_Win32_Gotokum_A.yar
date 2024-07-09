
rule TrojanDownloader_Win32_Gotokum_A{
	meta:
		description = "TrojanDownloader:Win32/Gotokum.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {2f 62 61 69 61 79 2e 74 78 74 00 00 39 31 36 32 00 00 00 00 64 61 68 2f 30 00 00 00 6d 2e 63 6e 2f 6b 73 00 2e 79 6f 75 6b 75 00 00 68 74 74 70 3a 2f 2f 39 30 37 36 35 } //1
		$a_00_1 = {d3 a6 d3 c3 b3 cc d0 f2 cd f8 c2 e7 b7 c3 ce ca bc e0 bf d8 } //1
		$a_00_2 = {6c 69 61 61 73 65 2e 65 78 65 } //1 liaase.exe
		$a_02_3 = {56 8b 74 24 08 68 ?? ?? 40 00 56 e8 d1 8d 00 00 68 ?? ?? 40 00 56 e8 d6 8d 00 00 68 ?? ?? 40 00 56 e8 cb 8d 00 00 68 ?? ?? 40 00 56 e8 c0 8d 00 00 68 ?? ?? 40 00 56 e8 b5 8d 00 00 68 ?? ?? 40 00 56 e8 aa 8d 00 00 83 c4 30 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*1) >=4
 
}

rule Ransom_Win32_GandCrab_ibt{
	meta:
		description = "Ransom:Win32/GandCrab!ibt,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 00 6f 00 7a 00 61 00 20 00 7a 00 65 00 6c 00 6f 00 37 00 50 00 75 00 67 00 75 00 20 00 79 00 65 00 77 00 6f 00 74 00 75 00 6e 00 65 00 64 00 6f 00 62 00 65 00 64 00 75 00 20 00 68 00 69 00 78 00 6f 00 74 00 69 00 77 00 69 00 20 00 72 00 6f 00 7a 00 61 00 63 00 6f 00 79 00 65 00 20 00 6d 00 69 00 62 00 61 00 20 00 74 00 69 00 79 00 75 00 70 00 69 00 68 00 61 00 6c 00 6f 00 78 00 75 00 } //1 Soza zelo7Pugu yewotunedobedu hixotiwi rozacoye miba tiyupihaloxu
		$a_01_1 = {63 00 6f 00 7a 00 61 00 6d 00 65 00 20 00 76 00 69 00 6a 00 69 00 68 00 61 00 20 00 72 00 61 00 62 00 65 00 6d 00 65 00 62 00 6f 00 70 00 6f 00 62 00 6f 00 7a 00 65 00 20 00 68 00 61 00 72 00 75 00 70 00 75 00 79 00 75 00 63 00 69 00 74 00 65 00 20 00 66 00 75 00 76 00 75 00 6b 00 75 00 79 00 69 00 64 00 65 00 64 00 69 00 79 00 65 00 20 00 6a 00 75 00 79 00 69 00 77 00 61 00 64 00 75 00 20 00 74 00 6f 00 78 00 61 00 7a 00 65 00 70 00 61 00 20 00 79 00 75 00 77 00 65 00 6e 00 65 00 73 00 69 00 68 00 75 00 68 00 6f 00 20 00 73 00 69 00 63 00 65 00 66 00 75 00 } //1 cozame vijiha rabemebopoboze harupuyucite fuvukuyidediye juyiwadu toxazepa yuwenesihuho sicefu
		$a_03_2 = {30 04 2e 83 ee 01 79 e5 5f 5e 5d 59 59 c3 90 09 13 00 81 fe ?? ?? 00 00 7d 06 ff 15 ?? ?? ?? 00 e8 b7 fe ff ff } //1
		$a_03_3 = {8b 45 08 8b 00 8b 4d f8 03 c1 8a 08 88 4d ?? 8a 48 ?? 88 4d ?? 8a 48 ?? 0f b6 40 ?? 50 8d 45 ?? 50 8d 45 ?? 50 8d 45 ?? 50 88 4d ?? e8 ?? ?? ?? ?? 8a 45 ?? 83 45 f8 ?? 88 04 3e 8a 45 ?? 83 c4 ?? 46 88 04 3e 8a 45 ?? 46 88 04 3e 8b 45 f8 46 3b 03 72 ac } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=2
 
}

rule TrojanSpy_Win32_Ifnapod_A{
	meta:
		description = "TrojanSpy:Win32/Ifnapod.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_02_0 = {83 fe 08 0f 84 ?? ?? 00 00 83 fe 0d 0f 84 ?? ?? 00 00 83 fe 2d 0f 84 ?? ?? 00 00 83 fe 56 74 44 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 6a 11 ff 15 ?? ?? 00 10 a8 80 } //1
		$a_02_1 = {39 7d 08 0f 85 ?? ?? 00 00 8b 45 0c 2d 01 02 00 00 74 20 83 e8 03 } //1
		$a_02_2 = {8b 45 10 8b 40 08 83 f8 10 0f 84 ?? ?? 00 00 3d ae 00 00 00 74 73 3d 02 03 00 00 } //1
		$a_00_3 = {49 6e 73 74 61 6c 6c 46 00 49 6e 73 74 61 6c 6c 46 4e 44 00 } //1 湉瑳污䙬䤀獮慴汬乆D
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
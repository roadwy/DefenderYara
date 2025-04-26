
rule TrojanSpy_Win32_Banker_AGA{
	meta:
		description = "TrojanSpy:Win32/Banker.AGA,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2d 10 01 00 00 c6 00 5c 8d 45 f8 03 85 e0 fe ff ff 2d 0f 01 00 00 c6 00 43 8d 45 f8 03 85 e0 fe ff ff 2d 0e 01 00 00 c6 00 41 8d 45 f8 03 85 e0 fe ff ff 2d 0d 01 00 00 c6 00 2e 8d 45 f8 03 85 e0 fe ff ff 2d 0c 01 00 00 c6 00 63 8d 45 f8 03 85 e0 fe ff ff 2d 0b 01 00 00 c6 00 65 8d 45 f8 03 85 e0 fe ff ff 2d 0a 01 00 00 c6 00 72 8d 45 f8 03 85 e0 fe ff ff 2d 09 01 00 00 } //1
		$a_01_1 = {5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 53 79 73 74 65 6d 00 43 6f 6e 73 65 6e 74 50 72 6f 6d 70 74 42 65 68 61 76 69 6f 72 41 64 6d 69 6e 00 45 6e 61 62 6c 65 4c 55 41 } //1 䍜牵敲瑮敖獲潩屮潐楬楣獥卜獹整m潃獮湥側潲灭䉴桥癡潩䅲浤湩䔀慮汢䱥䅕
		$a_01_2 = {5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 43 6f 6e 74 72 6f 6c 5c 53 65 72 76 69 63 65 47 72 6f 75 70 4f 72 64 65 72 00 4c 69 73 74 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
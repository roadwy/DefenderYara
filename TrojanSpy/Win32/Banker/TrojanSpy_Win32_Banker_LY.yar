
rule TrojanSpy_Win32_Banker_LY{
	meta:
		description = "TrojanSpy:Win32/Banker.LY,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {3d 50 c3 00 00 7e 3f ba 02 00 00 00 8b c3 e8 90 01 04 6a 01 6a 00 6a 00 8d 45 90 01 01 b9 90 01 04 8b 15 90 01 04 e8 90 01 04 8b 45 90 01 01 e8 90 01 04 50 68 90 01 04 6a 00 e8 90 00 } //1
		$a_03_1 = {33 f6 8d 9d 90 01 02 ff ff 8d 46 0c 3d 00 04 00 00 7d 30 80 3b 23 75 2b 80 7b 01 14 75 25 80 7b 02 62 75 1f 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
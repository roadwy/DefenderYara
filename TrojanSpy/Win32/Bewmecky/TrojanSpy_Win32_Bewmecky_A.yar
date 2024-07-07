
rule TrojanSpy_Win32_Bewmecky_A{
	meta:
		description = "TrojanSpy:Win32/Bewmecky.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {80 f9 40 74 04 3b ef 7c f3 33 f6 33 ff 85 ed 0f 8e 90 01 02 00 00 80 3c 38 23 0f 85 90 01 02 00 00 83 fb 01 75 1b 90 00 } //1
		$a_01_1 = {7e 1f 80 3c 32 5c 74 07 4a 3b d3 7f f5 eb 12 } //1
		$a_01_2 = {83 e8 05 8d 48 a4 83 f9 04 77 03 83 c0 1a 8d 48 c4 83 f9 04 77 03 83 c0 1a 8d 48 d5 83 f9 04 77 03 83 c0 0a ff 45 fc 88 04 37 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
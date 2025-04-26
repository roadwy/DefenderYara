
rule TrojanSpy_Win32_Banker_PE{
	meta:
		description = "TrojanSpy:Win32/Banker.PE,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {77 69 6e 64 69 72 00 00 ff ff ff ff 1d 00 00 00 a3 9b 90 88 91 93 90 9e 9b 9a 9b df 8f 8d 90 98 } //1
		$a_01_1 = {6f 70 65 6e 00 00 00 00 53 56 8b d8 33 d2 8b 83 } //1
		$a_03_2 = {8d 4d a8 33 d2 b8 ?? ?? ?? ?? e8 88 fa ff ff 8b 55 a8 58 e8 7f 5c fb ff 8b 45 ac e8 6f 5e fb ff 50 68 ?? ?? ?? ?? 6a 00 e8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}
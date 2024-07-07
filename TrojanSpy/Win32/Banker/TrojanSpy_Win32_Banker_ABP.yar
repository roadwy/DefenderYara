
rule TrojanSpy_Win32_Banker_ABP{
	meta:
		description = "TrojanSpy:Win32/Banker.ABP,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {8b 4b 70 ba 90 01 04 8b c6 e8 90 01 04 dd 43 40 d8 1d 90 01 04 df e0 9e 76 1f ff 73 44 ff 73 40 8d 55 f8 33 c0 e8 00 62 ff ff 8b 4d f8 ba 90 00 } //1
		$a_03_1 = {0f b6 44 10 ff 03 c7 b9 ff 00 00 00 99 f7 f9 8b da 3b 75 90 01 01 7d 03 46 eb 05 be 01 00 00 00 8b 45 90 01 01 0f b6 44 30 ff 33 d8 8d 45 90 01 01 50 89 5d 90 00 } //1
		$a_02_2 = {41 67 65 6e 63 69 61 90 02 21 43 6f 6e 74 61 90 02 50 53 65 6e 68 61 90 00 } //1
		$a_00_3 = {73 69 6c 65 6e 74 } //1 silent
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_02_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}

rule TrojanSpy_Win32_Banker_VCP{
	meta:
		description = "TrojanSpy:Win32/Banker.VCP,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 11 50 83 c3 01 56 52 0f 80 } //1
		$a_03_1 = {8b c8 0f bf c3 99 f7 f9 83 c2 01 0f 80 90 01 01 01 00 00 52 8b 55 08 90 00 } //1
		$a_03_2 = {ff d7 50 b9 50 00 00 00 ff 15 90 01 04 8b 55 90 01 01 50 8d 4d 90 01 01 8b 02 50 51 ff d7 8b 56 90 01 01 50 52 e8 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}

rule TrojanSpy_Win32_Tougle_D_bit{
	meta:
		description = "TrojanSpy:Win32/Tougle.D!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b 4c 24 18 8a 04 0a 32 c3 88 44 16 fc 8b 0d 90 01 04 8b 34 8d 90 01 04 8a 44 16 fc 84 c0 74 03 90 00 } //1
		$a_01_1 = {51 8b 44 24 08 80 38 6f 75 17 80 78 01 62 75 11 80 78 02 66 75 0b 80 78 03 3a 75 05 83 c0 04 59 c3 } //1
		$a_01_2 = {c7 02 6b 65 72 6e c7 45 38 65 6c 33 32 c7 45 3c 2e 64 6c 6c ff 55 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
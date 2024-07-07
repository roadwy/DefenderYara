
rule TrojanSpy_Win32_Wordapas_A{
	meta:
		description = "TrojanSpy:Win32/Wordapas.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_03_0 = {2e 74 50 6a 03 8d 85 90 01 01 ff ff ff 68 90 01 02 40 00 50 e8 90 01 02 00 00 83 c4 0c 85 c0 74 36 90 00 } //2
		$a_03_1 = {68 04 20 00 00 8d 85 90 01 02 ff ff 50 57 ff 15 90 01 02 40 00 39 9d 90 01 02 ff ff 89 9d 90 01 02 ff ff 76 56 90 00 } //2
		$a_03_2 = {5b 54 5d 00 33 c0 8d bd 90 01 02 00 00 66 ab aa 66 c7 85 90 01 02 00 00 71 00 33 c0 8d bd 90 01 02 00 00 ab aa 66 c7 85 90 01 02 00 00 77 00 33 c0 8d bd 90 01 02 00 00 ab aa 66 c7 85 90 01 02 00 00 65 00 90 00 } //2
		$a_03_3 = {e9 99 00 00 00 8d 85 90 01 02 ff ff 50 ff d6 83 f8 0d 0f 8e 9b 00 00 00 8d 85 90 01 02 ff ff 50 bf 90 01 02 40 00 ff d6 8d b4 90 01 02 ff ff ff 6a 0b 59 33 c0 f3 a6 75 7d 90 00 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_03_2  & 1)*2+(#a_03_3  & 1)*2) >=6
 
}
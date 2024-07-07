
rule TrojanSpy_Win32_Ifnapod_B{
	meta:
		description = "TrojanSpy:Win32/Ifnapod.B,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {76 0b 80 38 68 75 06 8b 40 01 89 46 0c ff 76 14 ff 76 10 ff 76 0c ff 76 04 e8 } //1
		$a_01_1 = {76 0e 80 39 68 75 09 39 59 01 8d 71 01 0f 94 c2 85 d2 75 0f 83 c0 04 eb ce 83 c7 14 83 3f 00 75 a9 eb 33 } //1
		$a_01_2 = {5f 50 72 6f 67 5f 48 6f 6f 6b 41 6c 6c 41 70 70 73 40 38 00 66 6e 44 4c 4c 00 66 6e 46 4e 44 00 } //1 偟潲彧潈歯汁䅬灰䁳8湦䱄L湦乆D
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}

rule TrojanSpy_Win32_Nivdort_EJ{
	meta:
		description = "TrojanSpy:Win32/Nivdort.EJ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {68 00 00 c0 00 e8 90 01 02 00 00 83 c4 04 90 02 10 8b 8d 90 02 10 51 68 00 00 30 00 8b 95 90 02 10 52 e8 90 00 } //2
		$a_03_1 = {ab d1 cb eb 90 02 10 8b 4d 0c eb 90 00 } //1
		$a_03_2 = {52 68 00 60 00 00 68 90 01 03 00 8b 85 90 01 02 ff ff 50 ff 15 90 00 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}
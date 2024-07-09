
rule TrojanSpy_Win32_Nivdort_EJ{
	meta:
		description = "TrojanSpy:Win32/Nivdort.EJ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {68 00 00 c0 00 e8 ?? ?? 00 00 83 c4 04 [0-10] 8b 8d [0-10] 51 68 00 00 30 00 8b 95 [0-10] 52 e8 } //2
		$a_03_1 = {ab d1 cb eb [0-10] 8b 4d 0c eb } //1
		$a_03_2 = {52 68 00 60 00 00 68 ?? ?? ?? 00 8b 85 ?? ?? ff ff 50 ff 15 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}
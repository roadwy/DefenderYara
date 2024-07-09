
rule TrojanDropper_Win32_Hupigon_EJ{
	meta:
		description = "TrojanDropper:Win32/Hupigon.EJ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 74 } //1 taskkill /f /t
		$a_03_1 = {56 55 53 ff d7 50 8b 44 24 ?? 6a 01 50 e8 ?? ?? 00 00 83 c4 10 } //1
		$a_03_2 = {52 6a 01 53 50 68 02 00 00 80 ff 95 ?? ?? ff ff 3b c3 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}
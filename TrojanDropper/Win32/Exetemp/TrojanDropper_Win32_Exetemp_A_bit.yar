
rule TrojanDropper_Win32_Exetemp_A_bit{
	meta:
		description = "TrojanDropper:Win32/Exetemp.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {80 04 01 de 41 3b ca 72 f7 } //1
		$a_03_1 = {6a 01 8d 3c 2e 53 53 57 68 ?? ?? ?? ?? 53 ff 15 ?? ?? ?? ?? 57 ff 15 ?? ?? ?? ?? 8d 74 06 01 3b 74 24 20 72 } //1
		$a_03_2 = {83 c4 10 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 6a 0a ff 15 ?? ?? ?? ?? 8b 54 24 ?? 8b 44 24 ?? 83 c2 10 83 c7 20 48 89 54 24 ?? 89 44 24 ?? 75 } //1
		$a_01_3 = {45 58 45 5f 74 65 6d 70 25 78 25 73 } //1 EXE_temp%x%s
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
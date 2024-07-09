
rule TrojanDropper_Win32_Bamital_gen_A{
	meta:
		description = "TrojanDropper:Win32/Bamital.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {80 3a e9 75 08 8b 4d 0c 2b ca 01 4a 01 c9 } //1
		$a_03_1 = {74 2b 8b 45 f4 83 78 04 04 75 11 ff 75 f4 e8 ?? ?? ?? ?? 8b 45 fc c9 } //1
		$a_03_2 = {5f 0b c0 74 30 ff 15 ?? ?? ?? ?? 3c 05 75 09 c7 45 ec 01 00 00 00 eb 1b 8d 45 f4 50 6a 04 8d 45 e8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}
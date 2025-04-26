
rule TrojanDropper_Win32_Jadtre_A{
	meta:
		description = "TrojanDropper:Win32/Jadtre.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {83 c0 03 ff e0 ff b5 90 09 06 00 8b ff 55 8b 45 f4 } //1
		$a_01_1 = {83 c0 c4 50 8b 45 fc 83 c0 3c 50 57 ff 15 } //1
		$a_01_2 = {c1 e8 08 25 ff 00 00 00 0f b6 c0 89 45 f8 83 7d f8 02 75 20 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
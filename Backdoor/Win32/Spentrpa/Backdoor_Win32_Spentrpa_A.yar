
rule Backdoor_Win32_Spentrpa_A{
	meta:
		description = "Backdoor:Win32/Spentrpa.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {ff d5 8d 54 24 14 68 ?? ?? ?? ?? 52 88 5c 04 1c e8 ?? ?? ?? ?? 83 c4 08 3b c3 74 a2 } //1
		$a_03_1 = {68 a8 61 00 00 51 52 ff d6 8b 15 ?? ?? ?? ?? 6a 00 8b 44 24 0c 8d 4c 24 10 50 51 52 ff d7 } //1
		$a_01_2 = {eb ca 8b 4c 24 18 3b cb 74 29 8a 41 ff 3a c3 74 18 3c ff 74 14 fe c8 5f 5e 88 41 ff } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
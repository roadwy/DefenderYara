
rule TrojanDropper_Win32_Xorer_B{
	meta:
		description = "TrojanDropper:Win32/Xorer.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8a c1 2c 61 3c 19 77 ?? 80 e9 47 eb ?? 8a c1 2c 30 3c 09 } //1
		$a_03_1 = {fe c2 0f be fa 81 ff ?? ?? 00 00 75 02 32 d2 30 14 30 40 3b c1 7c e9 } //1
		$a_01_2 = {75 02 33 c0 30 04 32 42 40 3b d1 7c ef } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
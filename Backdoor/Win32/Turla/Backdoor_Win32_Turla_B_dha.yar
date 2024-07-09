
rule Backdoor_Win32_Turla_B_dha{
	meta:
		description = "Backdoor:Win32/Turla.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {eb 76 8b c5 8d 50 01 8a 08 83 c0 01 3a cb 75 f7 2b c2 8d 54 24 20 52 83 c0 01 50 55 57 56 ff 15 } //1
		$a_03_1 = {8b 04 24 8b 4c 24 08 83 e9 04 0f 84 ?? ?? ?? ?? 83 e9 01 74 5a 83 e9 01 75 c3 8b 4c 24 0c 83 e9 00 74 36 83 e9 01 74 1b 83 e9 01 75 b0 f7 d8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
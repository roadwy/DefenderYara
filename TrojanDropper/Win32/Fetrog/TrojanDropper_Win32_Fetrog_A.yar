
rule TrojanDropper_Win32_Fetrog_A{
	meta:
		description = "TrojanDropper:Win32/Fetrog.A,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_01_0 = {69 d2 6d a9 33 60 b8 8f 3b 48 dd 2b c2 8b d0 c1 e8 08 30 01 } //10
		$a_03_1 = {68 00 24 89 85 51 c7 44 24 ?? 00 00 00 00 ff 15 ?? ?? ?? ?? 85 c0 74 10 81 7c 24 ?? 00 10 00 00 75 06 } //1
	condition:
		((#a_01_0  & 1)*10+(#a_03_1  & 1)*1) >=11
 
}
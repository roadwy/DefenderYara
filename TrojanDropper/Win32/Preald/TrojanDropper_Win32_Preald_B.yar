
rule TrojanDropper_Win32_Preald_B{
	meta:
		description = "TrojanDropper:Win32/Preald.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {4e 48 8a 14 01 88 10 85 f6 75 f5 } //1
		$a_03_1 = {47 8b f7 c1 e6 04 83 be ?? ?? ?? ?? 00 75 d1 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
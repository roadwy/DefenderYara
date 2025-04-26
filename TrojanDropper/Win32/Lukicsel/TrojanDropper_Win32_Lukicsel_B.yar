
rule TrojanDropper_Win32_Lukicsel_B{
	meta:
		description = "TrojanDropper:Win32/Lukicsel.B,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {33 c0 8a c3 b9 0c 00 00 00 33 d2 f7 f1 8a 04 16 8b ?? ?? 32 02 8b ?? ?? 88 02 ff ?? ?? ff ?? ?? 8b 06 b2 01 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
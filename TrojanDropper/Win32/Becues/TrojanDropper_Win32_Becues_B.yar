
rule TrojanDropper_Win32_Becues_B{
	meta:
		description = "TrojanDropper:Win32/Becues.B,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a c2 b2 03 f6 ea 02 44 34 ?? 32 d8 88 5c 34 ?? 46 3b f1 72 dc 6a 01 6a 00 f7 d9 51 57 ff 15 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
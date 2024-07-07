
rule TrojanDropper_Win32_Nuwar_gen_B{
	meta:
		description = "TrojanDropper:Win32/Nuwar.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {ff 75 14 ff 75 10 e8 90 01 02 ff ff 83 c4 90 01 01 39 f3 73 0b e8 90 01 02 ff ff 30 04 3b 43 eb f1 90 00 } //1
		$a_02_1 = {ff 75 14 ff 75 10 e8 90 01 02 ff ff 83 c4 90 01 01 39 90 01 01 73 18 e8 90 01 02 ff ff 50 0f b6 04 90 01 01 50 e8 90 01 02 ff ff 88 04 90 01 04 eb e4 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}
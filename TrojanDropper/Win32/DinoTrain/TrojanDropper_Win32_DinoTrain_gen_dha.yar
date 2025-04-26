
rule TrojanDropper_Win32_DinoTrain_gen_dha{
	meta:
		description = "TrojanDropper:Win32/DinoTrain.gen!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_43_0 = {c7 83 c4 90 01 01 03 da 33 c9 2b c2 74 90 01 01 8a 44 19 90 01 01 84 c0 74 90 01 01 30 04 19 8b 95 90 01 04 8b c7 41 2b c2 3b c8 72 90 00 00 } //1
	condition:
		((#a_43_0  & 1)*1) >=1
 
}

rule TrojanDropper_Win32_SplitLoader_B_dha{
	meta:
		description = "TrojanDropper:Win32/SplitLoader.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8b f8 0f 11 85 90 01 01 00 00 00 0f 11 8d 90 01 01 00 00 00 e8 90 01 04 41 b9 90 01 04 4c 8d 05 90 01 04 48 8d 54 24 40 48 8b cf e8 90 00 } //100
	condition:
		((#a_03_0  & 1)*100) >=100
 
}
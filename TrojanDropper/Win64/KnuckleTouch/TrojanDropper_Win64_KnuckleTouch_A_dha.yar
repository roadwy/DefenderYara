
rule TrojanDropper_Win64_KnuckleTouch_A_dha{
	meta:
		description = "TrojanDropper:Win64/KnuckleTouch.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 01 00 00 "
		
	strings :
		$a_01_0 = {69 f6 fd 43 03 00 33 d2 81 c6 c3 9e 26 00 8b c6 c1 e8 10 25 ff 7f 00 00 f6 c1 01 74 } //100
	condition:
		((#a_01_0  & 1)*100) >=100
 
}
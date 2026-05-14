
rule Trojan_Win64_Tinukebot_LR_MTB{
	meta:
		description = "Trojan:Win64/Tinukebot.LR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {33 d2 48 8d 7f 01 44 8b c8 8b c3 ff c3 41 f7 f1 0f b6 04 32 30 47 ff 3b dd } //20
		$a_01_1 = {44 30 01 48 8d 49 01 48 ff ca } //10
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}
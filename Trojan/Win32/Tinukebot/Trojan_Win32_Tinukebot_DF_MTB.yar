
rule Trojan_Win32_Tinukebot_DF_MTB{
	meta:
		description = "Trojan:Win32/Tinukebot.DF!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {03 c8 33 d2 f7 75 14 8b 45 10 8a 04 02 32 04 0b 88 01 50 33 c0 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}
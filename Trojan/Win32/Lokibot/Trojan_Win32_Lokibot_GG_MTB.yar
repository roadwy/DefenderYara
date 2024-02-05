
rule Trojan_Win32_Lokibot_GG_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.GG!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {90 90 8d 43 01 be 6e 00 00 00 33 d2 f7 f6 8b c1 03 c3 88 10 43 81 fb 58 39 70 1c } //01 00 
		$a_01_1 = {a1 64 6e 48 00 03 c3 8a 00 90 34 9e 8b 15 64 6e 48 00 03 d3 88 02 90 90 43 81 fb bd 56 00 00 75 df } //00 00 
	condition:
		any of ($a_*)
 
}
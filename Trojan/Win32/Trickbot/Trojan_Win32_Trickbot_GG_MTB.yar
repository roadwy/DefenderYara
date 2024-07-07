
rule Trojan_Win32_Trickbot_GG_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.GG!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 0c 8d 0c 06 33 d2 8b c6 f7 75 14 8b 45 08 8a 04 02 30 01 46 3b 75 10 75 e5 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
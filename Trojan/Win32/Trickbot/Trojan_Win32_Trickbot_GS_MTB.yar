
rule Trojan_Win32_Trickbot_GS_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.GS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {53 8b 5c 24 0c 55 56 8b 74 24 18 33 d2 8b c1 bd 90 02 04 f7 f5 8a 04 1a 30 04 31 41 3b cf 75 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
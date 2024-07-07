
rule Trojan_Win32_Pikabot_AS_MTB{
	meta:
		description = "Trojan:Win32/Pikabot.AS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 d2 8b c3 6a 90 01 01 59 f7 f1 8a 44 15 90 01 01 30 04 3b 43 81 fb 90 01 02 00 00 72 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
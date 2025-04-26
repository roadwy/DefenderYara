
rule Trojan_Win32_Pikabot_AS_MTB{
	meta:
		description = "Trojan:Win32/Pikabot.AS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 d2 8b c3 6a ?? 59 f7 f1 8a 44 15 ?? 30 04 3b 43 81 fb ?? ?? 00 00 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
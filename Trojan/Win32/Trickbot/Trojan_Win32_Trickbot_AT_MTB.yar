
rule Trojan_Win32_Trickbot_AT_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.AT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {6a 0a 33 d2 5b f7 f3 8b 45 08 8a 54 0a 04 30 54 08 0e 40 3b 07 89 45 08 72 e6 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
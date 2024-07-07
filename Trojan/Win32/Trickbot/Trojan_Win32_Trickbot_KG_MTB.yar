
rule Trojan_Win32_Trickbot_KG_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.KG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 45 fc 33 d2 b9 90 02 04 f7 f1 90 02 50 0f be 90 02 02 8b 55 90 01 01 0f be 90 01 01 33 90 01 01 8b 4d 90 01 01 88 90 01 01 e9 90 0a a0 00 8b 45 fc 83 c0 01 89 45 fc 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
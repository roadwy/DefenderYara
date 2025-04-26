
rule Trojan_Win32_Trickbot_KG_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.KG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 45 fc 33 d2 b9 [0-04] f7 f1 [0-50] 0f be [0-02] 8b 55 ?? 0f be ?? 33 ?? 8b 4d ?? 88 ?? e9 90 0a a0 00 8b 45 fc 83 c0 01 89 45 fc } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
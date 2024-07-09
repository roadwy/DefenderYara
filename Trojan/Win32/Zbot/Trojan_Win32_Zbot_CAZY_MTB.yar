
rule Trojan_Win32_Zbot_CAZY_MTB{
	meta:
		description = "Trojan:Win32/Zbot.CAZY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 d2 f7 f1 66 89 55 e8 8b 4d 08 33 4d e4 81 c1 ?? ?? ?? ?? 89 4d e4 0f b7 4d e8 23 4d e4 8b 55 f4 0f b6 04 0a 0f b6 4d ec 31 c8 88 45 e0 0f b7 4d e8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
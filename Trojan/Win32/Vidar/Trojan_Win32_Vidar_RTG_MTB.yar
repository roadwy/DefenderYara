
rule Trojan_Win32_Vidar_RTG_MTB{
	meta:
		description = "Trojan:Win32/Vidar.RTG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c8 8b 85 dc fe ff ff 33 d2 f7 f1 52 8d 8d ec fe ff ff e8 57 eb ff ff 0f b6 10 33 f2 8b 85 dc fe ff ff 0f b6 88 ?? ?? ?? ?? 33 ce 8b 95 dc fe ff ff 88 8a } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}

rule Trojan_Win32_TrickBot_HC_MTB{
	meta:
		description = "Trojan:Win32/TrickBot.HC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 fc 83 c0 01 33 d2 f7 35 ?? ?? ?? ?? 89 55 fc 8b 55 08 03 55 fc 0f b6 02 03 45 ec 33 d2 f7 35 ?? ?? ?? ?? 89 55 ec 8b 45 08 03 45 fc 8a 08 88 4d fb 8b 55 08 03 55 fc 8b 45 08 03 45 ec 8a 08 88 0a } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
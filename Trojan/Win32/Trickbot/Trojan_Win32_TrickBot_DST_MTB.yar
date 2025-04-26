
rule Trojan_Win32_TrickBot_DST_MTB{
	meta:
		description = "Trojan:Win32/TrickBot.DST!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {c7 45 fc 00 00 00 00 c7 45 e8 00 00 00 00 c7 45 fc 00 00 00 00 eb 09 8b 45 fc 83 c0 01 89 45 fc 81 7d fc 05 2e 00 00 0f 83 ?? ?? ?? ?? 8b 4d fc 0f b6 91 ?? ?? ?? ?? 89 55 f0 81 7d f0 ff 00 00 00 0f 87 ?? ?? ?? ?? 8b 45 f0 ff 24 85 90 09 07 00 c7 45 ec } //1
		$a_02_1 = {c7 45 f8 00 00 00 00 c7 45 e8 00 00 00 00 c7 45 f8 00 00 00 00 eb 09 8b 45 f8 83 c0 01 89 45 f8 81 7d f8 05 2e 00 00 0f 83 ?? ?? ?? ?? 8b 4d f8 0f b6 91 ?? ?? ?? ?? 89 55 f0 81 7d f0 ff 00 00 00 0f 87 ?? ?? ?? ?? 8b 45 f0 ff 24 85 90 09 07 00 c7 45 ec } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}
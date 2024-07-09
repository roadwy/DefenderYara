
rule Trojan_Win32_Pikabot_DH_MTB{
	meta:
		description = "Trojan:Win32/Pikabot.DH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {68 00 30 00 00 8b ?? f8 ?? 6a 00 ff 55 } //1
		$a_03_1 = {f7 f6 0f b6 54 15 ?? 33 ca 8b 85 ?? ?? ff ff 90 09 11 00 0f b6 0c ?? 8b 85 ?? ?? ff ff 33 d2 be } //1
		$a_03_2 = {5e 8b e5 5d c3 90 09 0e 00 88 0c ?? e9 ?? ?? ff ff ff 95 ?? ?? ff ff } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}
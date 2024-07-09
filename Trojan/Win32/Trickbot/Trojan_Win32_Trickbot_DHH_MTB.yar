
rule Trojan_Win32_Trickbot_DHH_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.DHH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {83 c4 10 6a 0a 68 ?? ?? ?? ?? 53 8b e8 ff 54 24 ?? 8b f0 56 53 ff 54 24 ?? 56 53 89 44 24 ?? ff 54 24 ?? 8b 4c 24 ?? 51 89 44 24 ?? ff 54 24 ?? 8b 94 24 ?? ?? ?? ?? 53 52 89 44 24 ?? 8b 44 24 ?? 68 00 30 00 00 50 53 ff d5 50 ff d7 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
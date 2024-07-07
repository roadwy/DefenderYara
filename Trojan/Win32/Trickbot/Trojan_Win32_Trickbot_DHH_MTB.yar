
rule Trojan_Win32_Trickbot_DHH_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.DHH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {83 c4 10 6a 0a 68 90 01 04 53 8b e8 ff 54 24 90 01 01 8b f0 56 53 ff 54 24 90 01 01 56 53 89 44 24 90 01 01 ff 54 24 90 01 01 8b 4c 24 90 01 01 51 89 44 24 90 01 01 ff 54 24 90 01 01 8b 94 24 90 01 04 53 52 89 44 24 90 01 01 8b 44 24 90 01 01 68 00 30 00 00 50 53 ff d5 50 ff d7 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
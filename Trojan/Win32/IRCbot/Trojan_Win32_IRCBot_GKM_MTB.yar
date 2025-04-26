
rule Trojan_Win32_IRCBot_GKM_MTB{
	meta:
		description = "Trojan:Win32/IRCBot.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {83 ec 04 c7 04 24 ?? ?? ?? ?? 5e 01 cf e8 ?? ?? ?? ?? b9 4b c6 13 ec 31 32 81 ef a3 38 7a 37 41 83 ec 04 89 0c 24 8b 0c 24 83 c4 04 81 c2 01 00 00 00 21 cf 01 c9 39 da 75 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
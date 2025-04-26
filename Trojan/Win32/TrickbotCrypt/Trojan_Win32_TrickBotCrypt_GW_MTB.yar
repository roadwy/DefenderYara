
rule Trojan_Win32_TrickBotCrypt_GW_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.GW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8a 04 0f 88 04 0e 88 1c 0f 0f b6 04 0e 0f b6 d3 03 c2 33 d2 bb ?? ?? ?? ?? f7 f3 8b 45 ?? 40 89 45 ?? 0f b6 1c 0a 8b 55 ?? 30 5c 10 ?? 3b 45 ?? 72 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}

rule Trojan_Win32_QakBot_G_MTB{
	meta:
		description = "Trojan:Win32/QakBot.G!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {88 f0 f6 e2 8b 75 ?? 8b 7d ?? 8a 14 3e 88 45 ?? 80 f6 ?? 88 75 ?? 2b 4d ?? 8b 5d ?? 88 14 3b 01 cf 8b 4d ?? 39 cf 89 7d ?? 75 90 09 10 00 8b 45 ?? b9 ?? ?? ?? ?? b2 ?? 8a 75 ?? 89 45 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
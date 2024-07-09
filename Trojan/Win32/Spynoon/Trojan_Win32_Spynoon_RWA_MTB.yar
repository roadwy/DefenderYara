
rule Trojan_Win32_Spynoon_RWA_MTB{
	meta:
		description = "Trojan:Win32/Spynoon.RWA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c4 04 8b 45 ?? 33 d2 b9 0a 00 00 00 f7 f1 0f b6 92 ?? ?? ?? ?? 8b 45 ?? 03 45 ?? 0f b6 08 33 ca 8b 55 ?? 03 55 ?? 88 0a 8b 45 ?? 8b 08 83 c1 01 8b 55 ?? 89 0a } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
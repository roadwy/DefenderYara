
rule Trojan_Win32_Gandcrab_GM_MTB{
	meta:
		description = "Trojan:Win32/Gandcrab.GM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b c7 c1 e8 05 03 45 ?? 8b cf c1 e1 04 03 4d ?? 33 c1 8b 4d ?? 81 45 fc ?? ?? ?? ?? 03 cf 33 c1 2b d8 ff 4d ?? 75 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Gandcrab_GM_MTB_2{
	meta:
		description = "Trojan:Win32/Gandcrab.GM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f be 18 e8 ?? ?? ?? ?? 33 d8 8b 4d ?? 03 4d ?? 88 19 eb 90 09 14 00 8d 55 ?? 52 6a ?? 6a ?? ff 15 ?? ?? ?? ?? 8b 45 ?? 03 45 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
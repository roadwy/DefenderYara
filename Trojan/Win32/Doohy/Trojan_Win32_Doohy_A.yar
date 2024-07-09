
rule Trojan_Win32_Doohy_A{
	meta:
		description = "Trojan:Win32/Doohy.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {74 34 6a 00 8d 85 ?? ?? ff ff 50 68 00 02 00 00 8d 8d ?? ?? ff ff 51 8b 95 ?? ?? ff ff 52 ff 15 ?? ?? 40 00 8b 85 ?? ?? ff ff 50 ff 15 ?? ?? 40 00 e9 e0 00 00 00 } //1
		$a_03_1 = {83 7d ec 00 74 27 6a 40 68 00 10 00 00 6a 15 8b ?? ?? c1 e2 0c 52 8b 45 08 50 ff 15 ?? ?? 40 00 89 45 fc 83 7d fc 00 74 02 eb 02 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
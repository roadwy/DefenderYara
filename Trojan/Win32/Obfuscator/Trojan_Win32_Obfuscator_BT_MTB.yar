
rule Trojan_Win32_Obfuscator_BT_MTB{
	meta:
		description = "Trojan:Win32/Obfuscator.BT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 55 fc 8d 84 02 ?? ?? ?? ?? 8b 4d 08 03 01 8b 55 08 89 02 8b 45 08 8b 08 81 e9 ?? ?? ?? ?? 8b 55 08 89 0a 8b e5 5d c3 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Obfuscator_BT_MTB_2{
	meta:
		description = "Trojan:Win32/Obfuscator.BT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {99 f7 f9 8b 84 ?? ?? ?? ?? ?? 8b 8c ?? ?? ?? ?? ?? 8a 94 ?? ?? ?? ?? ?? 30 14 08 40 89 84 24 ?? ?? ?? ?? 8b 84 24 ?? ?? ?? ?? 8b c8 48 85 c9 89 84 24 ?? ?? ?? ?? 0f } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}

rule Trojan_Win32_ICLoader_BAK_MTB{
	meta:
		description = "Trojan:Win32/ICLoader.BAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {c1 e2 04 a1 ?? ?? ?? 00 23 c2 a3 ?? ?? ?? 00 33 c9 8a 0d ?? ?? ?? 00 8b 15 ?? ?? ?? 00 83 e2 08 0f af ca a1 ?? ?? ?? 00 0b c1 a3 } //3
		$a_03_1 = {89 45 fc 8a 0d ?? ?? ?? 00 32 0d ?? ?? ?? 00 88 0d ?? ?? ?? 00 33 d2 8a 15 } //2
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}

rule Trojan_Win32_Androm_V_MTB{
	meta:
		description = "Trojan:Win32/Androm.V!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 45 e4 8b 4d ?? 83 e1 ?? 0f be 04 08 8b 4d ?? 0f b6 54 0d ?? 31 c2 88 d3 88 5c 0d ?? 8b 45 ?? 83 c0 ?? 89 45 ?? e9 } //2
		$a_02_1 = {8b 45 e4 8b 4d ?? 83 e1 ?? 0f be 04 08 8b 4d ?? 0f b6 14 0d ?? ?? ?? ?? 31 c2 88 d3 88 1c 0d ?? ?? ?? ?? 8b 45 ?? 83 c0 ?? 89 45 ?? e9 } //2
	condition:
		((#a_02_0  & 1)*2+(#a_02_1  & 1)*2) >=2
 
}

rule Trojan_Win32_Emotet_PA{
	meta:
		description = "Trojan:Win32/Emotet.PA,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b c0 8b c0 8b c0 8b c0 8b c0 8b c0 8b c0 8b c0 8b c0 8b c0 8b c0 8b c0 31 0d ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b ff c7 05 ?? ?? ?? ?? 00 00 00 00 8b ff 01 05 ?? ?? ?? ?? 8b ff 8b 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 89 11 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
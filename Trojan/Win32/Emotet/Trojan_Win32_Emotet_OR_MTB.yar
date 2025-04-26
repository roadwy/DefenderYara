
rule Trojan_Win32_Emotet_OR_MTB{
	meta:
		description = "Trojan:Win32/Emotet.OR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 d3 03 c2 99 b9 ?? ?? ?? ?? f7 f9 8b 4c 24 ?? 8b 44 24 ?? 41 89 4c 24 1c 8a 54 14 28 30 54 08 ff 3b ee 0f } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
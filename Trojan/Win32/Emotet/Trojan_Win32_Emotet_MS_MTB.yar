
rule Trojan_Win32_Emotet_MS_MTB{
	meta:
		description = "Trojan:Win32/Emotet.MS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {89 02 5f 5d c3 90 09 21 00 33 c1 ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 01 05 ?? ?? ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? a1 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Emotet_MS_MTB_2{
	meta:
		description = "Trojan:Win32/Emotet.MS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {b8 1b cb 06 00 b8 1b cb 06 00 b8 1b cb 06 00 b8 1b cb 06 00 b8 1b cb 06 00 b8 1b cb 06 00 b8 1b cb 06 00 b8 1b cb 06 00 b8 1b cb 06 00 b8 1b cb 06 00 a1 ?? ?? ?? ?? 33 c1 8b ff c7 05 ?? ?? ?? ?? 00 00 00 00 01 05 ?? ?? ?? ?? 8b ff 8b 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 89 02 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
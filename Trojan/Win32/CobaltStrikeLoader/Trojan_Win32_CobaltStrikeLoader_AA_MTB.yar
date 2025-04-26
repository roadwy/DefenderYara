
rule Trojan_Win32_CobaltStrikeLoader_AA_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrikeLoader.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {53 56 57 e8 ?? ?? ff ff 6a 00 6a 00 68 00 00 04 00 } //1
		$a_03_1 = {c7 45 ec ec ?? ?? ?? c7 45 f0 14 ?? ?? ?? c7 45 f4 3c ?? ?? ?? c7 45 f8 64 ?? ?? ?? c7 45 fc 8c ?? ?? ?? ff 15 ?? ?? ?? ?? 68 00 00 10 00 6a 00 50 ff 15 ?? ?? ?? ?? 8b d8 33 f6 8b fb } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
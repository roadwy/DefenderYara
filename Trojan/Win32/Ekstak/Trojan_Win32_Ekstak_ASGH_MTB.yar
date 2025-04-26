
rule Trojan_Win32_Ekstak_ASGH_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.ASGH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {51 56 ff 15 ?? ?? ?? 00 8b f0 c7 44 24 04 00 00 00 00 ff 15 ?? ?? ?? 00 68 ?? ?? ?? 00 a3 ?? ?? ?? 00 ff 15 ?? ?? ?? 00 8b 0d ?? ?? ?? 00 03 c8 85 f6 89 } //2
		$a_03_1 = {55 8b ec 83 ec 0c 53 56 57 e8 ?? ?? ?? ff 89 45 fc e9 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}
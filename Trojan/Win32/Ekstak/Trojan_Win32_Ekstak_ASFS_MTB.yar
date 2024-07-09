
rule Trojan_Win32_Ekstak_ASFS_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.ASFS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {51 56 ff 15 ?? ?? ?? 00 8b f0 ff 15 ?? ?? ?? 00 85 ff a3 ?? ?? ?? 00 74 27 85 f6 74 12 8b 15 ?? ?? ?? 00 68 ?? ?? ?? 00 52 ff 15 ?? ?? ?? 00 8d 44 24 08 50 57 ff 15 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
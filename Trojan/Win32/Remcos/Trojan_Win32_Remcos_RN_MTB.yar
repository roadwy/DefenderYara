
rule Trojan_Win32_Remcos_RN_MTB{
	meta:
		description = "Trojan:Win32/Remcos.RN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 04 30 ff 77 ?? 68 ?? ?? ?? ?? 81 04 24 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 81 04 24 ?? ?? ?? ?? ff d0 68 ?? ?? ?? ?? 5a b9 ?? ?? ?? ?? 8b 1c 0a 81 f3 ?? ?? ?? ?? 89 1c 08 83 e9 ?? 7d ?? ff e0 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
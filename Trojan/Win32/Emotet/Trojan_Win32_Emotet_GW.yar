
rule Trojan_Win32_Emotet_GW{
	meta:
		description = "Trojan:Win32/Emotet.GW,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {89 5d f0 81 6d f0 ?? ?? ?? ?? 35 ?? ?? ?? ?? 81 6d f0 ?? ?? ?? ?? 81 45 f0 ?? ?? ?? ?? c1 e8 02 81 6d f0 ?? ?? ?? ?? c1 eb 17 81 45 f0 ?? ?? ?? ?? 35 ?? ?? ?? ?? 81 45 f0 ?? ?? ?? ?? 81 6d f0 ?? ?? ?? ?? c1 e0 1a 81 6d f0 ?? ?? ?? ?? 81 45 f0 ?? ?? ?? ?? 8b 45 f0 } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}
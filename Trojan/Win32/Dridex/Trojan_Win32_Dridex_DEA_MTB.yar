
rule Trojan_Win32_Dridex_DEA_MTB{
	meta:
		description = "Trojan:Win32/Dridex.DEA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {b8 13 00 01 00 b8 13 00 01 00 b8 13 00 01 00 b8 13 00 01 00 b8 13 00 01 00 a1 ?? ?? ?? ?? a3 ?? ?? ?? ?? 31 0d ?? ?? ?? ?? c7 05 ?? ?? ?? ?? 00 00 00 00 a1 ?? ?? ?? ?? 01 05 ?? ?? ?? ?? 8b ff 8b 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 89 02 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}

rule Trojan_Win32_Dridex_DES_MTB{
	meta:
		description = "Trojan:Win32/Dridex.DES!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 55 fc 83 ea 51 2b 15 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 03 4d f8 8b 15 ?? ?? ?? ?? 89 91 ?? ?? ?? ?? 8b 45 fc 03 05 ?? ?? ?? ?? 03 45 fc a3 ?? ?? ?? ?? b9 01 00 00 00 6b d1 0b } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}

rule Trojan_Win32_Cridex_DEA_MTB{
	meta:
		description = "Trojan:Win32/Cridex.DEA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b ef 2b e8 8d 44 2a a5 81 fa ?? ?? ?? ?? 90 13 81 c3 ?? ?? ?? ?? 8d 44 0a fa 8b 15 ?? ?? ?? ?? 89 1d ?? ?? ?? ?? 89 9c 32 ?? ?? ?? ?? 8b 1d ?? ?? ?? ?? 8d 0c c3 03 c8 83 c6 04 89 0d } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
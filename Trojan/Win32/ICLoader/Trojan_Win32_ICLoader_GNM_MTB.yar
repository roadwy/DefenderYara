
rule Trojan_Win32_ICLoader_GNM_MTB{
	meta:
		description = "Trojan:Win32/ICLoader.GNM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 10 33 c8 8b c1 33 cf 5f 81 f9 ?? ?? ?? ?? 5e 75 ?? b9 ?? ?? ?? ?? 89 0d ?? ?? ?? ?? f7 d1 89 0d ?? ?? ?? ?? 83 c4 ?? c3 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
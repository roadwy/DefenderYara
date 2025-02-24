
rule Trojan_Win32_ICLoader_GNT_MTB{
	meta:
		description = "Trojan:Win32/ICLoader.GNT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {56 8b f1 6a 62 8a 0d ?? ?? ?? ?? 32 c8 88 0d ?? ?? ?? ?? 8a 0d } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
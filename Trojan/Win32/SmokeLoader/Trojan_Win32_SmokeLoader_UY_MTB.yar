
rule Trojan_Win32_SmokeLoader_UY_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.UY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {ae 00 c6 c6 c6 ?? 2d ?? ?? ?? ?? 32 d7 2e 20 38 39 39 5f 90 0a 28 00 e5 ?? a2 ?? ?? ?? ?? 02 c2 2d ?? ?? ?? ?? 34 ?? 2d } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
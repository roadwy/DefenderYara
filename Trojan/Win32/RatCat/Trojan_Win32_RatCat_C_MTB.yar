
rule Trojan_Win32_RatCat_C_MTB{
	meta:
		description = "Trojan:Win32/RatCat.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {56 66 83 3d ?? ?? ?? ?? 00 74 0f 83 3d ?? ?? ?? ?? 00 74 06 89 0d ?? ?? ?? ?? 8a 14 85 ?? ?? ?? ?? 8b 74 24 08 02 d1 88 14 30 40 3d ?? ?? ?? ?? 7c cf } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
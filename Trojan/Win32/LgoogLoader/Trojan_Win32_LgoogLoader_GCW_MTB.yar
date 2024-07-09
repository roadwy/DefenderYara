
rule Trojan_Win32_LgoogLoader_GCW_MTB{
	meta:
		description = "Trojan:Win32/LgoogLoader.GCW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 02 33 c1 8b 0d ?? ?? ?? ?? 03 4d c4 88 01 eb 90 0a 32 00 0f b6 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 03 55 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
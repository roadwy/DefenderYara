
rule Trojan_Win64_SpyLoader_SL_MTB{
	meta:
		description = "Trojan:Win64/SpyLoader.SL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 63 f9 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? 48 ?? ?? ?? 48 ?? ?? ?? 01 d6 6b d6 ?? 29 d7 48 ?? ?? 42 ?? ?? ?? 32 14 0b 88 14 08 48 ?? ?? 8b 95 ?? ?? ?? ?? 48 ?? ?? 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
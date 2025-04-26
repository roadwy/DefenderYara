
rule Trojan_Win64_BazarLoader_SB_MTB{
	meta:
		description = "Trojan:Win64/BazarLoader.SB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f 45 d8 41 8b 4e ?? 4c 8d 8c 24 ?? ?? ?? ?? 41 8b 56 ?? 8b c3 0f ba e8 ?? 41 81 e0 ?? ?? ?? ?? 0f 44 c3 48 03 ce 44 8b c0 8b d8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
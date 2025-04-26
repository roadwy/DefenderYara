
rule Trojan_Win64_Emotet_SAE_MTB{
	meta:
		description = "Trojan:Win64/Emotet.SAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 f9 8b c2 48 98 48 ?? ?? ?? ?? ?? ?? ?? 0f b6 04 01 8b 4c 24 ?? 33 c8 8b c1 48 ?? ?? ?? ?? 48 ?? ?? ?? ?? 88 04 0a eb } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
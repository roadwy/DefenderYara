
rule Trojan_Win64_Emotet_SAC_MTB{
	meta:
		description = "Trojan:Win64/Emotet.SAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c2 c1 e8 ?? 03 d0 41 ?? ?? 41 ?? ?? 8d 0c d2 03 c9 2b c1 48 ?? ?? 48 ?? ?? ?? ?? ?? ?? 8a 0c 01 43 ?? ?? ?? 41 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
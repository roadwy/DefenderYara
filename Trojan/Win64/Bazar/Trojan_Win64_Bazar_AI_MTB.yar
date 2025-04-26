
rule Trojan_Win64_Bazar_AI_MTB{
	meta:
		description = "Trojan:Win64/Bazar.AI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 31 d2 49 f7 f1 45 8a 14 ?? 44 30 14 0f 48 ff c1 48 89 c8 48 81 f9 ?? ?? ?? ?? 76 e3 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}

rule Trojan_Win64_Emotet_SAA_MTB{
	meta:
		description = "Trojan:Win64/Emotet.SAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {49 ff c1 41 f7 e0 41 8b c0 41 ff c0 c1 ea ?? 6b d2 ?? 2b c2 48 ?? ?? 42 ?? ?? ?? ?? 42 ?? ?? ?? ?? 41 ?? ?? ?? 44 ?? ?? 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
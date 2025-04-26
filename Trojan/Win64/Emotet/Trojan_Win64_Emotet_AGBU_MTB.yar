
rule Trojan_Win64_Emotet_AGBU_MTB{
	meta:
		description = "Trojan:Win64/Emotet.AGBU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {ff c1 41 f7 e0 41 8b c0 41 ff c0 c1 ea ?? 8d 0c 92 c1 e1 ?? 2b c1 48 63 c8 42 0f b6 04 11 41 32 44 29 ff 41 88 41 ff 45 3b c4 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}

rule Trojan_Win64_Emotet_SAA_MTB{
	meta:
		description = "Trojan:Win64/Emotet.SAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {49 ff c1 41 f7 e0 41 8b c0 41 ff c0 c1 ea 90 01 01 6b d2 90 01 01 2b c2 48 90 01 02 42 90 01 04 42 90 01 04 41 90 01 03 44 90 01 02 72 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
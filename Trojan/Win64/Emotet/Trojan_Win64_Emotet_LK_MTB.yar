
rule Trojan_Win64_Emotet_LK_MTB{
	meta:
		description = "Trojan:Win64/Emotet.LK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 04 24 c1 e8 0d 8b 0c 24 c1 e1 13 0b c1 89 04 24 48 8b 44 24 20 0f be 00 83 f8 61 7c 11 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
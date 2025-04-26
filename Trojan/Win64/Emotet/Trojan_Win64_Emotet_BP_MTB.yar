
rule Trojan_Win64_Emotet_BP_MTB{
	meta:
		description = "Trojan:Win64/Emotet.BP!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 63 c8 48 8b 84 24 30 03 00 00 0f b6 04 08 8b d7 33 d0 48 63 8c 24 b8 03 00 00 48 8b 84 24 b0 03 00 00 88 14 08 e9 47 fd ff ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
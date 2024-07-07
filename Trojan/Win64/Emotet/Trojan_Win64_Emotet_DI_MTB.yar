
rule Trojan_Win64_Emotet_DI_MTB{
	meta:
		description = "Trojan:Win64/Emotet.DI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 63 4c 24 30 48 8b 44 24 60 44 0f b6 04 08 8b 44 24 30 99 b9 3f 00 00 00 f7 f9 48 63 ca 48 8b 44 24 20 0f b6 04 08 41 8b d0 33 d0 48 63 4c 24 30 48 8b 44 24 28 88 14 08 eb } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}

rule Trojan_Win64_Emotet_BZ_MTB{
	meta:
		description = "Trojan:Win64/Emotet.BZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 98 0f b6 7c 04 90 01 01 8b 84 24 90 01 04 99 b9 90 01 04 f7 f9 48 63 ca 48 8b 05 90 01 04 0f b6 04 08 8b d7 33 d0 8b 0d 90 01 04 8b 84 24 90 01 04 03 c1 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
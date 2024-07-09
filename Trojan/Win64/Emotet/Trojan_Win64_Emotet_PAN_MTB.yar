
rule Trojan_Win64_Emotet_PAN_MTB{
	meta:
		description = "Trojan:Win64/Emotet.PAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 c8 f7 ea c1 fa ?? 89 c8 c1 f8 ?? 29 c2 89 d0 01 c0 01 d0 c1 e0 ?? 89 ca 29 c2 48 63 c2 4c 01 d0 0f b6 00 44 31 c8 41 88 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
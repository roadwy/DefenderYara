
rule Trojan_Win64_Emotet_ACMMS_MTB{
	meta:
		description = "Trojan:Win64/Emotet.ACMMS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {4c 8b c8 48 2b f0 b8 90 01 04 41 f7 e8 c1 fa 90 01 01 8b c2 c1 e8 90 01 01 03 d0 49 63 c0 41 83 c0 01 48 63 ca 48 6b c9 90 01 01 48 03 c8 48 8d 05 90 01 04 8a 04 01 42 32 04 0e 41 88 01 49 83 c1 01 44 3b c5 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
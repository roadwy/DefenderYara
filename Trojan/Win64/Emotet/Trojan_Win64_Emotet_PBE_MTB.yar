
rule Trojan_Win64_Emotet_PBE_MTB{
	meta:
		description = "Trojan:Win64/Emotet.PBE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {4c 8b c8 48 2b f8 41 8b c0 41 83 c0 ?? 99 83 e2 ?? 03 c2 83 e0 ?? 2b c2 48 63 c8 48 8d 05 [0-04] 8a 04 01 42 32 04 0f 41 88 01 49 83 c1 ?? 44 3b c6 72 } //1
		$a_03_1 = {41 f7 e8 c1 fa ?? 8b c2 c1 e8 ?? 03 d0 49 63 c0 41 83 c0 ?? 48 63 ca 48 6b c9 ?? 48 03 c8 48 8d 05 [0-04] 8a 04 01 42 32 04 0f 41 88 01 49 83 c1 ?? 44 3b c6 72 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}
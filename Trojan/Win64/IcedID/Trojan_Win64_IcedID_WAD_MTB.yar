
rule Trojan_Win64_IcedID_WAD_MTB{
	meta:
		description = "Trojan:Win64/IcedID.WAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {49 63 c8 48 8b c3 48 f7 e1 41 ff c0 48 c1 ea ?? 48 6b c2 16 48 2b c8 8a 44 8d 97 41 30 01 49 ff c1 44 3b c7 72 } //1
		$a_03_1 = {49 63 ca 48 8b c3 48 f7 e1 41 ff c2 48 c1 ea ?? 48 6b c2 16 48 2b c8 8a 44 8d f7 41 30 00 49 ff c0 44 3b d7 72 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}

rule Trojan_Win64_Emotet_CPP_MTB{
	meta:
		description = "Trojan:Win64/Emotet.CPP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {49 63 c4 41 83 c4 90 01 01 48 63 ca 48 6b c9 90 01 01 48 03 c8 48 8b 44 24 28 42 0f 90 01 07 41 32 4c 00 ff 43 88 4c 18 ff 44 3b 64 24 20 72 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
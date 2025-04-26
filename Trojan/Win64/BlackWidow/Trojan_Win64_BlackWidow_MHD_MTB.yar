
rule Trojan_Win64_BlackWidow_MHD_MTB{
	meta:
		description = "Trojan:Win64/BlackWidow.MHD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {44 03 de 48 f7 e1 48 8b c1 48 2b c2 48 d1 e8 48 03 c2 48 c1 e8 ?? 48 6b c0 19 48 2b c8 8a 44 0c 20 42 32 04 13 41 88 02 4c 03 d6 45 3b dc 72 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
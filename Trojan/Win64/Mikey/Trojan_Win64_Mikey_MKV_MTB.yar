
rule Trojan_Win64_Mikey_MKV_MTB{
	meta:
		description = "Trojan:Win64/Mikey.MKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 89 f1 4c 6b d2 50 4c 01 d0 48 83 c0 40 44 33 18 44 89 de 89 f0 4c 03 8c 24 b0 00 00 00 89 4c 24 44 4c 89 c9 48 89 54 24 38 4c 89 c2 49 89 c0 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
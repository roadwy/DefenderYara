
rule Trojan_Win64_Tedy_NOP_MTB{
	meta:
		description = "Trojan:Win64/Tedy.NOP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c0 07 31 d2 49 f7 f1 41 8a 04 10 48 8b 14 24 30 04 11 48 8b 44 24 ?? 48 83 c0 05 31 d2 49 f7 f1 48 89 54 24 20 48 8b 04 24 48 ff c0 48 89 44 24 ?? 8b 05 e3 63 68 00 8d 50 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}

rule Trojan_Win64_Tedy_DKZ_MTB{
	meta:
		description = "Trojan:Win64/Tedy.DKZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8d 50 4f 30 14 08 48 ff c0 48 83 f8 03 72 f1 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}

rule Trojan_Win64_Rozena_ASG_MTB{
	meta:
		description = "Trojan:Win64/Rozena.ASG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f 1f 00 80 30 90 01 01 48 8d 40 01 ff c1 81 f9 90 01 04 72 ef 48 8d 84 24 90 01 04 45 33 c9 48 89 44 24 90 01 01 33 d2 33 c9 c7 44 24 20 90 01 04 ff 15 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
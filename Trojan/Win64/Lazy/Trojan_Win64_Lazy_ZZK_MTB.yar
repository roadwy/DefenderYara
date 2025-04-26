
rule Trojan_Win64_Lazy_ZZK_MTB{
	meta:
		description = "Trojan:Win64/Lazy.ZZK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8d 50 7a 30 14 08 48 ff c0 48 83 f8 0a 72 f1 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
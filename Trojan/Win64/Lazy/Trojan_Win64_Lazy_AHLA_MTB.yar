
rule Trojan_Win64_Lazy_AHLA_MTB{
	meta:
		description = "Trojan:Win64/Lazy.AHLA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8b c2 4a 8d 0c 2a 83 e0 7f 48 ff c2 0f b6 84 18 80 00 00 00 32 04 0f 88 01 48 3b d5 72 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
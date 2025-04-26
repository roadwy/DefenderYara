
rule Trojan_Win64_Lazy_BV_MTB{
	meta:
		description = "Trojan:Win64/Lazy.BV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 44 24 20 ff c0 89 44 24 20 8b 44 24 48 39 44 24 20 7d 20 48 63 44 24 20 48 8b 4c 24 40 0f be 04 01 83 f0 31 48 63 4c 24 20 48 8b 54 24 28 88 04 0a eb } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
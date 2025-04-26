
rule Trojan_Win64_Lazy_GZT_MTB{
	meta:
		description = "Trojan:Win64/Lazy.GZT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {49 8b c9 66 90 8d 41 8b 30 04 0a 48 ff c1 48 83 f9 0c 72 f1 c6 42 0d 00 4c 89 4d a8 48 8d 42 0c 48 3b d0 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
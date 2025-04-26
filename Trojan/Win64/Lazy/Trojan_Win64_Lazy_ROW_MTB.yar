
rule Trojan_Win64_Lazy_ROW_MTB{
	meta:
		description = "Trojan:Win64/Lazy.ROW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 f7 e0 c1 ea 04 0f be c2 6b c8 32 41 8a c0 2a c1 04 32 41 30 01 41 ff c0 49 ff c1 41 83 f8 02 7c d9 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
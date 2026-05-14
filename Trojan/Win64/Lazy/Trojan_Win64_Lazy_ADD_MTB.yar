
rule Trojan_Win64_Lazy_ADD_MTB{
	meta:
		description = "Trojan:Win64/Lazy.ADD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {f7 e7 c1 ea 05 0f be c2 6b c8 33 40 8a c7 ff c7 2a c1 04 38 41 30 00 49 ff c0 83 ff 1c 7c } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
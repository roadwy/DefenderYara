
rule Trojan_Win64_Lazy_AC_MTB{
	meta:
		description = "Trojan:Win64/Lazy.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {80 f2 00 80 e2 01 45 88 c2 41 80 f2 01 41 80 e2 00 44 08 d2 41 88 c2 41 80 f2 ff 41 88 d3 41 80 f3 ff 44 88 c3 80 f3 01 45 08 da 80 cb 01 41 80 f2 ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
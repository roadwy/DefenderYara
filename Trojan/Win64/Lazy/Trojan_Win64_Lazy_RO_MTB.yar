
rule Trojan_Win64_Lazy_RO_MTB{
	meta:
		description = "Trojan:Win64/Lazy.RO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {44 31 f5 41 5e 55 81 34 24 91 87 ff 5d 59 81 f1 91 87 ff 5d 5d 44 01 f1 41 5e 48 81 ec 08 00 00 00 41 56 8f 04 24 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
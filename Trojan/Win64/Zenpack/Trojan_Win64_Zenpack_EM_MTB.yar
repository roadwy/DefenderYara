
rule Trojan_Win64_Zenpack_EM_MTB{
	meta:
		description = "Trojan:Win64/Zenpack.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8d 7d c8 f2 ae 48 f7 d1 48 ff c9 48 63 f9 8b c1 99 2b c2 d1 f8 85 c0 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
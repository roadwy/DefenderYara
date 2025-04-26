
rule Trojan_Win64_BumbleBee_FEM_MTB{
	meta:
		description = "Trojan:Win64/BumbleBee.FEM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {ff c0 48 63 c8 48 8b 44 24 60 ff c3 42 0f b6 8c 01 d0 89 01 00 48 ff c2 42 32 8c 02 4f 8a 01 00 88 4c 02 ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
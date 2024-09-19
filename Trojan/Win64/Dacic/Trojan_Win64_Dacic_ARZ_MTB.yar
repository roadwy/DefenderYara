
rule Trojan_Win64_Dacic_ARZ_MTB{
	meta:
		description = "Trojan:Win64/Dacic.ARZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {f7 eb d1 fa 8b c2 c1 e8 1f 03 d0 0f be c2 6b c8 37 0f b6 c3 2a c1 04 38 41 30 00 ff c3 4d 8d 40 01 83 fb 41 7c d5 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
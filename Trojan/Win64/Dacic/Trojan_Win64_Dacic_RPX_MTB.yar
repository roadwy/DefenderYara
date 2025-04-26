
rule Trojan_Win64_Dacic_RPX_MTB{
	meta:
		description = "Trojan:Win64/Dacic.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {b8 95 20 4f 09 f7 e9 d1 fa 8b c2 c1 e8 1f 03 d0 0f be c2 6b d0 37 0f b6 c1 2a c2 04 39 41 30 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win64_Dacic_RPX_MTB_2{
	meta:
		description = "Trojan:Win64/Dacic.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {f7 e9 d1 fa 8b c2 c1 e8 1f 03 d0 0f be c2 6b d0 37 0f b6 c1 2a c2 04 39 41 30 00 ff c1 4d 8d 40 01 83 f9 19 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
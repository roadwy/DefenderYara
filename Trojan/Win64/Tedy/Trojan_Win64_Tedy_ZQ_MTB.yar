
rule Trojan_Win64_Tedy_ZQ_MTB{
	meta:
		description = "Trojan:Win64/Tedy.ZQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 44 33 ?? 31 f8 88 44 33 ?? 48 89 fa 48 c1 fa ?? 31 d0 48 89 fa 48 c1 fa ?? 31 d0 48 89 fa 48 83 c7 ?? 48 c1 fa ?? 31 d0 88 44 33 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
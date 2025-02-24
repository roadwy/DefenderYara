
rule Trojan_Win64_Tedy_PYZ_MTB{
	meta:
		description = "Trojan:Win64/Tedy.PYZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {b8 9d 82 97 53 41 f7 e8 c1 fa 04 8b c2 c1 e8 1f 03 d0 0f be c2 6b c8 31 41 0f b6 c0 2a c1 04 33 41 30 01 41 ff c0 4d 8d 49 01 41 83 f8 21 7c d0 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
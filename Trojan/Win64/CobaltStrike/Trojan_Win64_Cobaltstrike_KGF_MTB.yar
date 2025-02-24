
rule Trojan_Win64_Cobaltstrike_KGF_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.KGF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {44 0f af 83 98 00 00 00 8b 83 60 01 00 00 ff c8 31 83 88 01 00 00 48 8b 83 f8 00 00 00 41 8b d0 c1 ea 10 88 14 01 41 8b d0 ff 83 ac 00 00 00 48 63 8b ac 00 00 00 48 8b 83 f8 00 00 00 c1 ea 08 88 14 01 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win64_Cobaltstrike_KGF_MTB_2{
	meta:
		description = "Trojan:Win64/Cobaltstrike.KGF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 89 ea 45 31 db 41 89 f2 41 c1 e2 ?? 49 01 da 31 c0 41 0f b6 0c 82 30 0c 02 48 83 c0 01 48 83 f8 04 75 } //5
		$a_03_1 = {48 83 c2 01 49 89 c2 c0 e8 04 83 e0 0f 41 83 e2 ?? 48 c1 e0 04 4c 01 e0 42 0f b6 04 10 88 42 ff 48 39 d1 75 } //4
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*4) >=9
 
}
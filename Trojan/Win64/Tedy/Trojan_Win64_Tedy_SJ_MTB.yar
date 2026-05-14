
rule Trojan_Win64_Tedy_SJ_MTB{
	meta:
		description = "Trojan:Win64/Tedy.SJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {89 44 24 54 41 8d 4e 01 41 b8 70 02 00 00 8b c2 c1 e8 1e 33 c2 69 d0 ?? ?? ?? ?? 03 d1 89 54 8c 54 48 ff c1 49 3b c8 72 e5 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
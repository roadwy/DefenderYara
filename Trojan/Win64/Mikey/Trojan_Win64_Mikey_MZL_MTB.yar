
rule Trojan_Win64_Mikey_MZL_MTB{
	meta:
		description = "Trojan:Win64/Mikey.MZL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {44 89 c9 83 f1 ff 81 e1 1e a6 7f 9b 41 ba ff ff ff ff 41 81 f2 1e a6 7f 9b 45 21 d1 44 89 c2 83 f2 ff 81 e2 1e a6 7f 9b 45 21 d0 44 09 c9 44 09 c2 31 d1 88 08 e9 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
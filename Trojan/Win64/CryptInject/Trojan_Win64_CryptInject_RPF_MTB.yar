
rule Trojan_Win64_CryptInject_RPF_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.RPF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {4d eb 4c 54 94 87 68 b3 9f dd 3f e0 f3 ac 30 b1 f5 54 3a da ad f6 e2 ae 01 6e 8e ec 02 6b 8b da 8a 74 78 76 d7 57 6a ee 5a bf 45 c7 4c e2 49 97 0f 49 97 b2 b8 c6 4c 93 0a 70 ca c9 7b 1b } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
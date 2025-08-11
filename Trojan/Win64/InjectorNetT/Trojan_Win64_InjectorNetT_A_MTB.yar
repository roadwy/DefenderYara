
rule Trojan_Win64_InjectorNetT_A_MTB{
	meta:
		description = "Trojan:Win64/InjectorNetT.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 45 66 8a 4d 67 88 c2 80 f2 ff 80 e2 01 41 b0 01 45 88 c1 41 80 f1 01 41 88 c2 45 20 ca 44 08 d2 80 f2 ff 80 f2 01 80 e2 ff 45 88 c1 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
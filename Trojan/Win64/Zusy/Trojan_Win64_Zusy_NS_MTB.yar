
rule Trojan_Win64_Zusy_NS_MTB{
	meta:
		description = "Trojan:Win64/Zusy.NS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 8d 0d 81 2e 00 00 ff 15 c3 2a 00 00 48 8d 3d a0 2e 00 00 48 8b d7 48 8d 4d ?? e8 30 02 00 00 } //3
		$a_03_1 = {45 33 c9 48 8d 15 56 2f 00 00 33 c9 ff 15 46 2b 00 00 48 8d 4d ?? e8 65 00 00 00 4c 8b c0 } //1
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*1) >=4
 
}
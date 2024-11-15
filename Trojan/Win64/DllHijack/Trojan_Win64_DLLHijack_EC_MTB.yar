
rule Trojan_Win64_DLLHijack_EC_MTB{
	meta:
		description = "Trojan:Win64/DLLHijack.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 08 48 8d 40 01 80 c1 4b 80 f1 3f 80 e9 4b 88 48 ff 48 83 ea 01 75 e7 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}

rule Trojan_Win64_DLLHijack_DI_MTB{
	meta:
		description = "Trojan:Win64/DLLHijack.DI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 63 c2 48 8d 4c 24 20 48 03 c8 0f b6 01 41 88 00 44 88 11 41 0f b6 08 49 03 ca 0f b6 c1 0f b6 4c 04 20 30 0b 48 ff c3 49 83 eb 01 75 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}
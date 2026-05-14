
rule Trojan_Win64_DLLHijack_CH_MTB{
	meta:
		description = "Trojan:Win64/DLLHijack.CH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {49 63 ca 8a 44 0c 40 88 44 14 40 88 5c 0c 40 0f b6 44 14 40 03 c3 0f b6 c0 8a 54 04 40 41 30 11 49 ff c1 49 83 eb 01 75 a0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}

rule Trojan_Win64_AsyncRAT_B_MTB{
	meta:
		description = "Trojan:Win64/AsyncRAT.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 00 48 98 0f b6 44 05 a0 83 f0 90 01 01 89 c2 8b 85 cc 90 01 01 01 00 48 98 88 54 05 a0 83 85 cc 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
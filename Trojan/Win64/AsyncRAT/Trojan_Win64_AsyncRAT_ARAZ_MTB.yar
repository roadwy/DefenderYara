
rule Trojan_Win64_AsyncRAT_ARAZ_MTB{
	meta:
		description = "Trojan:Win64/AsyncRAT.ARAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8b 45 f8 48 01 d0 0f b6 00 83 f0 55 89 c2 48 8d 0d ?? ?? 0c 00 48 8b 45 f8 48 01 c8 88 10 48 83 45 f8 01 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
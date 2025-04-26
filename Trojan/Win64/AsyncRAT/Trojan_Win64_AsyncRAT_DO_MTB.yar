
rule Trojan_Win64_AsyncRAT_DO_MTB{
	meta:
		description = "Trojan:Win64/AsyncRAT.DO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 98 0f b6 44 05 a0 83 f0 63 89 c2 8b 85 [0-04] 48 98 88 54 05 a0 83 85 [0-04] 01 8b 85 [0-04] 3d 01 73 01 00 76 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}
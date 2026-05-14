
rule Trojan_Win64_GhostRAT_ARAC_MTB{
	meta:
		description = "Trojan:Win64/GhostRAT.ARAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f b6 14 02 30 91 50 ac 00 10 46 81 e6 ff 00 00 80 79 08 } //2
		$a_01_1 = {5c 52 65 6c 65 61 73 65 5c 64 64 64 2e 70 64 62 } //2 \Release\ddd.pdb
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}
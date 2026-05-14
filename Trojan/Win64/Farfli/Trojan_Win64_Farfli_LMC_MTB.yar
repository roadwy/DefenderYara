
rule Trojan_Win64_Farfli_LMC_MTB{
	meta:
		description = "Trojan:Win64/Farfli.LMC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 0f b6 0c 29 4c 8b 43 10 49 ff c1 b8 ?? ?? ?? ?? f7 e9 03 d1 c1 fa 08 8b c2 c1 e8 1f 03 d0 b8 ?? ?? ?? ?? 69 d2 c8 01 00 00 2b ca 41 f7 e2 80 c1 36 43 30 0c 03 c1 ea 03 8d 0c 92 03 c9 44 3b d1 4d 0f 44 cf 41 ff c2 49 ff c3 44 3b d7 } //30
	condition:
		((#a_03_0  & 1)*30) >=30
 
}
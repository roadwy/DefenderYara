
rule Trojan_Win64_Lazy_LMX_MTB{
	meta:
		description = "Trojan:Win64/Lazy.LMX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_03_0 = {4c 31 0c c3 48 ff c0 48 3b c1 72 ?? 83 e2 07 76 ?? 49 8d 0c ce 4c 8d 85 b0 08 00 00 4c 2b c1 } //20
		$a_01_1 = {83 e2 07 76 20 49 8d 0c ce 4c 8d 85 b0 08 00 00 4c 2b c1 90 41 0f b6 04 08 30 01 48 8d 49 01 48 83 ea 01 } //10
	condition:
		((#a_03_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}
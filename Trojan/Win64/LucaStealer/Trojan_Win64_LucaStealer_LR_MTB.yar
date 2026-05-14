
rule Trojan_Win64_LucaStealer_LR_MTB{
	meta:
		description = "Trojan:Win64/LucaStealer.LR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {80 e1 07 c0 e1 03 48 d3 ea 43 30 14 08 4c 03 c3 49 83 f8 10 } //20
		$a_01_1 = {80 e1 07 b8 ff 00 00 00 c0 e1 03 48 d3 ea 66 23 d0 66 43 31 14 41 4c 03 c3 49 83 f8 0d } //10
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}
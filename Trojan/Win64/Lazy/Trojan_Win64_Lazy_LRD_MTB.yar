
rule Trojan_Win64_Lazy_LRD_MTB{
	meta:
		description = "Trojan:Win64/Lazy.LRD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {41 0f be 0a 41 c1 c9 0d 41 80 3a 61 8d 41 e0 0f 4d c8 49 ff c2 44 03 c9 48 83 ea 01 } //20
		$a_03_1 = {44 8b ee 4c 0f af 6b 30 44 8b fe 4c 03 6b 28 4c 39 5b 58 74 ?? 41 8b ff 48 0f af 7b 60 48 03 7b 58 } //10
	condition:
		((#a_01_0  & 1)*20+(#a_03_1  & 1)*10) >=30
 
}

rule Trojan_Win64_Redline_YAB_MTB{
	meta:
		description = "Trojan:Win64/Redline.YAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {66 43 40 66 f7 e9 4e c1 e9 34 81 f1 ?? ?? ?? ?? 66 8b fe ba 20 00 00 00 4f 2b c3 66 4e 66 33 f3 4a 66 49 66 42 66 c1 df ?? c1 ca 9d 66 23 ce 66 b8 f3 } //1
		$a_03_1 = {83 c4 0c 69 f6 ?? ?? ?? ?? 83 c7 04 8b c1 c1 e8 18 33 c1 69 c0 ?? ?? ?? ?? 33 f0 89 45 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}
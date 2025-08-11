
rule Trojan_Win64_Zusy_LMG_MTB{
	meta:
		description = "Trojan:Win64/Zusy.LMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 03 00 00 "
		
	strings :
		$a_01_0 = {48 8b 44 24 20 48 63 48 04 48 8b 44 0c 68 48 f7 d8 1b d2 f7 d2 83 e2 04 0b 54 0c 30 83 e2 15 83 ca 02 89 54 0c 30 23 54 0c 34 } //15
		$a_03_1 = {8b c8 c1 e9 1e 33 c8 69 c1 65 89 07 6c 03 c2 89 44 95 14 ?? ?? ?? 49 3b d0 72 e5 44 89 45 10 [0-04] 48 8d 45 10 } //10
		$a_03_2 = {f2 0f 59 05 ?? ?? ?? ?? 0f 57 c9 48 85 c0 78 ?? f2 48 0f 2a c8 eb ?? 48 8b c8 48 d1 e9 83 e0 01 48 0b c8 f2 48 0f 2a c9 f2 0f 58 c9 } //5
	condition:
		((#a_01_0  & 1)*15+(#a_03_1  & 1)*10+(#a_03_2  & 1)*5) >=30
 
}
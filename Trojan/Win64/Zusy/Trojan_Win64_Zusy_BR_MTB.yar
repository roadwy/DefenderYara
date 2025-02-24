
rule Trojan_Win64_Zusy_BR_MTB{
	meta:
		description = "Trojan:Win64/Zusy.BR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {80 74 24 21 ?? 80 74 24 22 ?? 80 74 24 23 ?? 80 74 24 24 ?? 80 74 24 25 ?? 80 74 24 26 ?? 80 74 24 27 ?? 66 89 4c 24 28 80 f1 ?? 80 74 24 29 ?? 34 ?? c6 44 24 20 49 88 44 24 2a 48 8d 44 24 20 88 4c 24 28 } //4
		$a_03_1 = {c1 e8 1f 03 d0 0f be c2 6b d0 ?? 0f b6 c1 ff c1 2a c2 04 ?? 41 30 40 ff 83 f9 } //1
		$a_03_2 = {c1 e8 1f 03 d0 b8 01 00 00 00 2a c2 0f be c0 6b d0 ?? 02 d1 ff c1 41 30 50 ff 83 f9 } //1
	condition:
		((#a_03_0  & 1)*4+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=5
 
}
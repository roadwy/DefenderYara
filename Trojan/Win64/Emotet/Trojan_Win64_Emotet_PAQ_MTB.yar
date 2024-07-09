
rule Trojan_Win64_Emotet_PAQ_MTB{
	meta:
		description = "Trojan:Win64/Emotet.PAQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 89 e8 48 d1 ?? 49 f7 e6 48 c1 ea ?? 48 6b fa ?? 48 89 d9 48 89 f2 } //1
		$a_03_1 = {48 89 c1 e8 [0-04] 48 03 [0-06] 8a 44 3d ?? 42 32 44 25 ?? 41 88 44 2d ?? 48 ff c5 48 81 fd [0-04] 0f 85 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
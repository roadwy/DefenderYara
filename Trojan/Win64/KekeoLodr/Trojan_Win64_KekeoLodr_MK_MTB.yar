
rule Trojan_Win64_KekeoLodr_MK_MTB{
	meta:
		description = "Trojan:Win64/KekeoLodr.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 89 f0 44 89 f1 48 83 c7 ?? 48 d3 f8 41 30 44 1c ?? 49 39 fd 75 ?? 48 ff c6 48 83 c3 ?? 71 } //1
		$a_03_1 = {48 ff c3 42 88 54 37 10 83 e3 0f 49 ff c6 e9 90 0a 22 00 48 8d 0d ?? ?? ?? ?? 42 8a 54 35 ?? 32 94 19 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
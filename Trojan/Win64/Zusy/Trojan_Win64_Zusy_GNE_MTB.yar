
rule Trojan_Win64_Zusy_GNE_MTB{
	meta:
		description = "Trojan:Win64/Zusy.GNE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f be 04 17 48 ff c2 03 c3 69 d8 01 01 00 00 8b c3 c1 e8 06 33 d8 48 3b d1 } //5
		$a_03_1 = {63 66 43 91 c7 05 ?? ?? ?? ?? 02 94 5b 0a c7 05 ?? ?? ?? ?? 81 d9 9b 36 c7 05 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}
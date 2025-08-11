
rule Trojan_Win64_Lazy_FY_MTB{
	meta:
		description = "Trojan:Win64/Lazy.FY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {66 0f 6f c7 48 8d 4c 24 30 0f 57 c6 33 d2 66 0f 7f 44 24 30 ff ?? ?? ?? ?? ?? 48 89 05 e7 27 23 00 48 85 c0 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
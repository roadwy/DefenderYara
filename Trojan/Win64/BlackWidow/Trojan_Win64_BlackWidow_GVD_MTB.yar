
rule Trojan_Win64_BlackWidow_GVD_MTB{
	meta:
		description = "Trojan:Win64/BlackWidow.GVD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {44 30 14 0f [0-10] 48 ff c1 [0-10] 48 89 c8 [0-10] 48 81 f9 [0-10] 90 13 [0-10] 48 31 d2 [0-10] 49 f7 f0 [0-10] 45 8a 14 11 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
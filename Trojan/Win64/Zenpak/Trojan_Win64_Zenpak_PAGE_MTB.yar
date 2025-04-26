
rule Trojan_Win64_Zenpak_PAGE_MTB{
	meta:
		description = "Trojan:Win64/Zenpak.PAGE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {83 f9 03 75 05 8b ce 48 8b d6 } //2
		$a_01_1 = {41 30 00 ff c1 48 ff c2 49 ff c0 49 ff c9 75 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}
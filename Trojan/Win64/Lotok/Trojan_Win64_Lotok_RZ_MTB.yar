
rule Trojan_Win64_Lotok_RZ_MTB{
	meta:
		description = "Trojan:Win64/Lotok.RZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 c7 c1 78 56 34 12 48 ff c9 4d 33 c9 48 8b c1 75 f5 48 33 c0 48 8b c3 48 03 c2 90 90 90 49 ff ca 4d 33 db 75 da 48 33 c0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
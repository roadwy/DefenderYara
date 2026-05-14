
rule Trojan_Win64_Mikey_WD_MTB{
	meta:
		description = "Trojan:Win64/Mikey.WD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {80 34 11 f9 48 ff c1 48 8b 5d a0 48 8b c3 48 8b 55 98 48 2b c2 48 3b c8 72 e6 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}

rule Trojan_Win64_Fabookie_RPZ_MTB{
	meta:
		description = "Trojan:Win64/Fabookie.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {80 00 09 eb 19 8b 73 30 49 8b e3 41 5d 41 5c 5f c3 cc cc cc cc cc cc 48 8b c4 48 89 58 08 48 ff c0 48 83 e9 01 75 d9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
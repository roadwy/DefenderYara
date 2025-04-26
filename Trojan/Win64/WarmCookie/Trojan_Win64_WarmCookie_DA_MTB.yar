
rule Trojan_Win64_WarmCookie_DA_MTB{
	meta:
		description = "Trojan:Win64/WarmCookie.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {46 0f be 54 0a 01 42 0f be 74 0a 02 41 c1 e2 02 c1 fe 06 41 83 e2 3c 83 e6 03 41 09 f2 4d 63 d2 47 8a 14 13 44 88 50 ?? 46 8a 54 0a 02 49 83 c1 03 41 83 e2 3f 47 8a 14 13 44 88 50 ?? e9 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
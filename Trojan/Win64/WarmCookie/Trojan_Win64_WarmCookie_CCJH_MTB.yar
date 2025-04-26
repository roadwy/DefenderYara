
rule Trojan_Win64_WarmCookie_CCJH_MTB{
	meta:
		description = "Trojan:Win64/WarmCookie.CCJH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 03 c8 48 8b c1 0f b6 00 0f b6 4c 24 20 48 8b 54 24 40 0f b6 4c 0a 02 33 c1 48 8b 4c 24 28 48 8b 54 24 50 48 03 d1 48 8b ca 88 01 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}

rule Trojan_Win64_Zusy_GZH_MTB{
	meta:
		description = "Trojan:Win64/Zusy.GZH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 c1 c0 20 49 89 01 49 03 00 49 89 00 48 33 02 48 c1 c8 ?? 48 89 02 4c 8b 11 4c 03 54 24 ?? 4c 01 d0 48 89 01 49 33 01 48 c1 c8 ?? 49 89 01 49 03 00 49 89 00 48 33 02 48 d1 c0 48 89 02 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}

rule Trojan_Win64_RedCurl_DA_MTB{
	meta:
		description = "Trojan:Win64/RedCurl.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8b 07 4c 8d 0c 02 48 8b c3 48 83 7b 18 10 72 ?? 48 8b 03 0f b6 14 01 41 32 11 48 8b c6 48 83 7e 18 10 72 ?? 48 8b 06 88 14 01 41 ff c0 48 ff c1 49 63 c0 48 3b 43 10 72 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
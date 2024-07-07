
rule Trojan_Win64_Fabookie_NFR_MTB{
	meta:
		description = "Trojan:Win64/Fabookie.NFR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {c7 45 e0 48 8b c4 48 eb 23 05 90 01 04 48 33 c4 48 89 84 24 90 01 04 48 8b e9 45 33 e4 48 8d 44 24 20 be 90 01 04 4c 8b cd c7 45 e4 89 58 08 4c 90 00 } //5
		$a_03_1 = {e9 8e 01 00 00 48 8d 4c 24 90 01 01 ff 15 91 98 ff ff 48 8d 4c 24 20 ff 15 7e 98 ff ff 41 3b c4 75 38 48 8b 0d 8a 2f 03 00 c7 45 ec 89 50 10 55 90 00 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}

rule Trojan_Win64_Dridex_GZS_MTB{
	meta:
		description = "Trojan:Win64/Dridex.GZS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {48 8b 44 24 08 8b 4c 24 3c 89 4c 24 3c 48 8b 54 24 28 44 8a 04 02 4c 8b 4c 24 30 4c 89 4c 24 40 66 c7 44 24 4e 90 01 02 4c 8b 54 24 50 49 81 c2 90 01 04 48 c7 44 24 40 90 01 04 4c 8b 5c 24 18 45 88 04 03 4d 29 c9 4c 89 4c 24 40 4c 01 d0 69 4c 24 3c 3a 17 70 4d 89 4c 24 3c 8b 4c 24 3c 33 4c 24 3c 89 4c 24 3c 4c 8b 4c 24 20 4c 39 c8 48 89 44 24 08 74 10 eb 87 90 00 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
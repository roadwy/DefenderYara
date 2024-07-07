
rule Trojan_Win64_Fabookie_GJS_MTB{
	meta:
		description = "Trojan:Win64/Fabookie.GJS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 89 4c 24 58 48 8d 88 90 01 04 48 89 4c 24 38 48 8d 80 90 01 04 48 89 44 24 48 48 8d 78 28 48 8d 47 0e 48 8d 48 0e 48 89 8c 24 a0 00 00 00 48 8d 49 08 48 89 8c 24 90 01 04 48 8d 49 0f 48 89 4c 24 40 48 8d 49 0a 48 89 4c 24 78 48 8d 49 12 48 89 4c 24 70 48 8d 49 12 48 89 4c 24 68 4c 8d 69 15 49 8d 75 0d 48 89 c1 48 8b 44 24 38 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
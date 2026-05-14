
rule Trojan_Win64_Mikey_PAA_MTB{
	meta:
		description = "Trojan:Win64/Mikey.PAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 04 24 48 8b 4c 24 20 0f b6 09 33 c8 8b c1 48 8b 4c 24 20 88 01 0f b6 04 24 48 8b 4c 24 20 0f b6 09 2b c8 8b c1 48 8b 4c 24 20 88 01 48 8b 44 24 20 48 ff c0 48 89 44 24 20 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
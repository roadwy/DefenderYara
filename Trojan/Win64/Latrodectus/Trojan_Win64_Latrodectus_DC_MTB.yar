
rule Trojan_Win64_Latrodectus_DC_MTB{
	meta:
		description = "Trojan:Win64/Latrodectus.DC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b7 03 48 8d 7c 24 40 49 8d 0c 86 41 8b 03 42 8b 2c 09 49 03 c1 eb ?? 3a 0f 75 ?? 48 ff c0 48 ff c7 8a 08 84 c9 75 ?? 8a 08 41 8b d0 41 8b c0 3a 0f 0f 97 c2 38 0f 0f 97 c0 3b d0 74 ?? 41 ff c2 48 83 c3 02 49 83 c3 04 44 3b d6 7c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
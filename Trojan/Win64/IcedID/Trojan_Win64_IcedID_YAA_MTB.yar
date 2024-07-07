
rule Trojan_Win64_IcedID_YAA_MTB{
	meta:
		description = "Trojan:Win64/IcedID.YAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 c8 41 f7 eb c1 fa 03 89 c8 c1 f8 1f 29 c2 44 8d 04 52 43 8d 04 c0 41 89 c8 41 29 c0 4d 63 c0 4c 8b 0d 90 01 04 47 0f b6 04 01 44 32 44 0c 20 45 88 04 0a 48 83 c1 01 48 81 f9 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}

rule Trojan_Win64_Convagent_MB_MTB{
	meta:
		description = "Trojan:Win64/Convagent.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 d2 48 8b 44 24 28 b9 20 00 00 00 48 f7 f1 48 8b c2 48 8b 0d 90 01 04 0f b6 04 01 48 8d 0d 90 01 04 48 8b 54 24 28 0f b6 0c 11 33 c8 8b c1 48 8b 4c 24 28 48 8b 54 24 48 48 03 d1 48 8b ca 88 01 eb 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
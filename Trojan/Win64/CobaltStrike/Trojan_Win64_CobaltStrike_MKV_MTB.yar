
rule Trojan_Win64_CobaltStrike_MKV_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.MKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {45 33 c0 c7 44 24 20 90 01 04 48 8d 55 90 01 01 48 8d 4b 90 01 01 e8 90 01 04 8b d3 4c 8d 45 90 01 01 41 0f b6 90 01 01 4d 8d 40 90 01 01 48 63 c2 80 f1 69 48 03 45 90 01 01 ff c2 88 08 81 fa 90 01 04 76 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}

rule Trojan_Win64_NightHawk_JK_MTB{
	meta:
		description = "Trojan:Win64/NightHawk.JK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {ff c0 89 44 24 90 01 01 8b 44 24 90 01 01 48 3d 90 01 04 73 90 01 01 8b 44 24 90 01 01 48 8b 4c 24 90 01 01 0f b6 04 01 83 f0 90 01 01 8b 4c 24 90 01 01 88 84 0c 90 01 04 eb 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
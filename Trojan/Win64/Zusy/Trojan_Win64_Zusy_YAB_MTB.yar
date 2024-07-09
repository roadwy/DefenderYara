
rule Trojan_Win64_Zusy_YAB_MTB{
	meta:
		description = "Trojan:Win64/Zusy.YAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f af c2 41 8b d1 c1 ea 10 89 05 7f 04 04 00 49 63 88 ?? ?? ?? ?? 49 8b 80 ?? ?? ?? ?? 88 14 01 41 8b d1 48 8b 05 5c 03 04 00 c1 ea 08 ff 80 88 00 00 00 48 8b 05 4c 03 04 00 48 63 88 88 00 00 00 48 8b 80 b0 00 00 00 88 14 01 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
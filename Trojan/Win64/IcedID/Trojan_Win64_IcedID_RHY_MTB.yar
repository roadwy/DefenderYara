
rule Trojan_Win64_IcedID_RHY_MTB{
	meta:
		description = "Trojan:Win64/IcedID.RHY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {45 8b 0c 02 49 83 c2 04 8b 81 c4 00 00 00 35 a8 a5 f3 00 09 81 0c 01 00 00 48 8b 15 1a d4 04 00 8b 8a ?? ?? ?? ?? 8b 82 48 01 00 00 81 f1 a9 a5 f3 00 0f af c1 89 82 48 01 00 00 48 63 0d 70 d4 04 00 44 0f af 0d 64 d4 04 00 48 8b 05 a1 d4 04 00 41 8b d1 c1 ea 18 88 14 01 41 8b d1 44 8b 05 4e d4 04 00 48 8b 0d cf d3 04 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
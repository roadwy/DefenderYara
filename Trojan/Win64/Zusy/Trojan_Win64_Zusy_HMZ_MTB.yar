
rule Trojan_Win64_Zusy_HMZ_MTB{
	meta:
		description = "Trojan:Win64/Zusy.HMZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 c1 0f b6 c1 8a 84 04 ?? ?? ?? ?? 48 63 8c 24 84 00 00 00 48 8b 54 24 48 30 04 0a 8b 84 24 84 00 00 00 83 c0 01 89 44 24 70 8b 05 ?? ?? ?? ?? 8d 48 ff 0f af c8 f6 c1 01 b8 17 f9 ce f2 b9 47 a4 cc 08 0f 44 c1 83 3d a6 5a 09 00 0a 0f 4c c1 44 8b 74 24 44 4d 89 ef e9 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
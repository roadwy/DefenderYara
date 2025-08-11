
rule Trojan_Win64_Vidar_BOZ_MTB{
	meta:
		description = "Trojan:Win64/Vidar.BOZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 c1 0f b6 c1 48 8b 4d b0 8a 04 01 48 63 4d ?? 48 8b 55 88 30 04 0a 44 8b 5d ?? 41 83 c3 01 b8 c1 04 f3 84 44 8b 4d a0 4c 8b 45 80 44 8b 75 ?? 44 8b 6d 94 8b 5d 98 3d 12 dd 65 dd 0f 8f } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
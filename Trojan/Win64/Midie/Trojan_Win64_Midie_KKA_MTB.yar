
rule Trojan_Win64_Midie_KKA_MTB{
	meta:
		description = "Trojan:Win64/Midie.KKA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8b 45 f0 8b 4d ec 48 8b 55 f8 4c 63 c9 49 b8 ?? ?? ?? ?? ?? 00 00 00 47 8a 0c 08 41 89 c8 41 ba ab aa aa aa 4d 0f af c2 49 c1 e8 23 45 89 c2 41 c1 e2 02 45 89 d0 47 8d 04 40 41 89 ca 45 29 c2 45 89 d3 49 b8 ?? ?? ?? ?? ?? 00 00 00 4d 01 d8 4d 63 d2 45 32 08 4c 63 c1 46 88 0c 02 83 c1 01 89 08 } //20
	condition:
		((#a_03_0  & 1)*20) >=20
 
}

rule Trojan_Win64_Strikco_A_bit{
	meta:
		description = "Trojan:Win64/Strikco.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 98 41 b9 40 00 00 00 41 b8 00 10 00 00 48 89 c2 b9 00 00 00 00 48 8b 05 ?? ?? ?? ?? ff d0 48 89 45 f0 c7 45 fc 00 00 00 00 eb 57 8b 45 fc 48 98 48 89 c1 48 03 4d 10 8b 45 fc 48 98 48 03 45 10 44 0f b6 00 8b 45 fc 89 c2 c1 fa 1f c1 ea 1e 01 d0 83 e0 03 29 d0 48 98 48 03 45 20 0f b6 00 44 31 c0 88 01 8b 45 fc 48 98 48 89 c2 48 03 55 10 8b 45 fc 48 98 48 03 45 f0 0f b6 12 88 10 83 45 fc 01 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
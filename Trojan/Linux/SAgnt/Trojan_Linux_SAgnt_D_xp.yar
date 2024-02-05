
rule Trojan_Linux_SAgnt_D_xp{
	meta:
		description = "Trojan:Linux/SAgnt.D!xp,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {48 83 ec 20 89 7d ec 48 90 01 02 e0 be 01 00 00 00 bf 11 00 00 00 e8 89 fd ff ff bf a7 0c 40 00 e8 90 01 02 ff ff 48 8b 45 e0 48 8b 00 48 89 c7 e8 90 01 02 ff ff 48 89 c2 b9 a9 0c 40 00 48 8b 45 e0 48 8b 00 48 89 ce 48 89 c7 90 00 } //01 00 
		$a_03_1 = {48 c1 e0 03 48 03 45 e0 48 8b 00 48 89 c7 e8 90 01 02 ff ff 48 89 c2 8b 45 fc 48 98 48 c1 e0 03 48 03 45 e0 48 8b 00 be 20 00 00 00 48 89 c7 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
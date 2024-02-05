
rule Ransom_Win32_Ruyk_A_ibt{
	meta:
		description = "Ransom:Win32/Ruyk.A!ibt,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {83 7d f4 08 7d 28 8b 45 fc 83 e0 01 74 10 8b 4d fc d1 e9 81 f1 20 83 b8 ed 89 4d f0 eb 08 8b 55 fc d1 ea 89 55 f0 } //01 00 
		$a_01_1 = {8b 45 0c 89 45 ec 8b 4d 0c 83 e9 01 89 4d 0c 83 7d ec 00 74 29 8b 55 08 0f b6 02 33 45 fc 25 ff 00 00 00 8b 4d fc c1 e9 08 33 8c 85 ec fb ff ff 89 4d fc 8b 55 08 83 c2 01 89 55 08 eb c2 } //00 00 
	condition:
		any of ($a_*)
 
}
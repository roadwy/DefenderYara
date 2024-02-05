
rule Trojan_Win32_NSISInject_EJ_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.EJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 05 00 "
		
	strings :
		$a_01_0 = {6a 40 68 00 30 00 00 50 56 ff 15 } //05 00 
		$a_01_1 = {89 44 24 04 c7 44 24 08 00 30 00 00 c7 44 24 0c 40 00 00 00 89 4d cc ff 15 } //01 00 
		$a_03_2 = {8b 75 f0 40 eb 90 01 01 8b 45 f0 ff e0 c2 ce 3e 43 41 81 e2 d7 30 01 00 43 81 fb 5f 7a 01 00 74 90 01 01 81 f2 c8 e5 00 00 4a 81 f3 40 9c 00 00 ba ff 47 00 00 c2 1e 6e 90 00 } //01 00 
		$a_03_3 = {89 45 d8 e9 90 01 02 ff ff 8b 45 ec ff e0 83 c4 4c 5e 5b 5d c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
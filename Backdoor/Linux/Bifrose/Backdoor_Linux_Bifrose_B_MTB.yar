
rule Backdoor_Linux_Bifrose_B_MTB{
	meta:
		description = "Backdoor:Linux/Bifrose.B!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 02 00 00 05 00 "
		
	strings :
		$a_02_0 = {c7 45 c4 ff ff ff ff 83 ec 0c 68 90 01 03 08 e8 90 01 04 83 c4 10 83 ec 04 6a 06 6a 01 6a 02 e8 90 01 04 83 c4 10 89 45 c4 83 7d c4 00 79 12 83 ec 0c 6a 0a e8 90 01 04 83 c4 10 e9 90 00 } //05 00 
		$a_02_1 = {48 63 05 56 55 20 00 48 6b c0 3e 4a 8d 14 28 41 0f bf 4c 05 3c bf b8 5d 40 00 31 c0 e8 90 01 04 bf c4 5d 40 00 31 c0 e8 90 01 04 bf 02 00 00 00 be 01 00 00 00 ba 06 00 00 00 e8 90 01 04 41 89 c4 45 85 e4 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
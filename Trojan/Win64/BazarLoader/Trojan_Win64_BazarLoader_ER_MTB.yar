
rule Trojan_Win64_BazarLoader_ER_MTB{
	meta:
		description = "Trojan:Win64/BazarLoader.ER!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 02 00 00 0a 00 "
		
	strings :
		$a_00_0 = {41 0f af d2 83 e2 01 83 fa 00 41 0f 94 c3 41 83 f8 0a 0f 9c c3 40 88 de 40 80 f6 ff 44 88 df 40 30 f7 44 20 df 44 88 de 40 80 f6 ff 41 88 de 41 20 f6 80 f3 ff } //03 00 
		$a_81_1 = {5a 72 6a 79 71 79 73 48 6a 79 67 62 68 6f 65 6a 79 7a 52 6a 6d 68 6f 7a 72 6a 74 } //00 00 
	condition:
		any of ($a_*)
 
}
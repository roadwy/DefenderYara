
rule Trojan_Linux_Sliver_AC_MTB{
	meta:
		description = "Trojan:Linux/Sliver.AC!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {4c 8d 64 24 f8 4d 3b 66 10 0f 86 2f 05 00 00 48 81 ec 88 00 00 00 48 89 ac 24 80 00 00 00 48 8d ac 24 80 00 00 00 48 89 84 24 90 00 00 00 48 89 9c 24 98 00 00 00 48 85 c0 0f 84 d4 04 00 00 8b 48 10 81 f9 6d 54 1a b3 0f 87 57 02 00 00 81 f9 8c 02 25 79 0f 87 30 01 00 00 66 0f 1f 44 00 00 81 f9 fb 7f a2 2e 0f 87 83 00 00 00 81 f9 c5 06 ff 13 75 36 } //01 00 
		$a_00_1 = {73 6c 69 76 65 72 70 62 2e 70 77 64 } //00 00  sliverpb.pwd
	condition:
		any of ($a_*)
 
}
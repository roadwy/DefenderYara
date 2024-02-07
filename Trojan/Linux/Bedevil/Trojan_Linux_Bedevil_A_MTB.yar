
rule Trojan_Linux_Bedevil_A_MTB{
	meta:
		description = "Trojan:Linux/Bedevil.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {49 43 4d 50 20 62 61 63 6b 64 6f 6f 72 20 75 70 } //01 00  ICMP backdoor up
		$a_00_1 = {41 63 63 65 70 74 20 62 61 63 6b 64 6f 6f 72 20 70 6f 72 74 } //03 00  Accept backdoor port
		$a_00_2 = {55 89 e5 56 53 81 ec 50 01 00 00 e8 31 7b ff ff 81 c3 d1 cf 00 00 e8 d6 73 ff ff 85 c0 75 09 e8 8d 75 ff ff 85 c0 74 05 e9 85 02 00 00 8d 83 90 b4 ff ff 89 04 24 e8 26 6d ff ff e8 11 77 ff ff 89 45 f0 83 7d f0 00 74 05 e9 64 02 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}
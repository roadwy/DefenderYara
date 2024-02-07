
rule Trojan_Win64_BumbleBee_SE_MTB{
	meta:
		description = "Trojan:Win64/BumbleBee.SE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {c7 45 e3 22 23 00 00 81 f2 90 01 04 44 89 6d 90 01 01 8b 88 90 01 04 81 c1 90 01 04 c7 45 ef 90 01 04 c7 45 eb 90 01 04 3b ca 77 90 00 } //01 00 
		$a_03_1 = {48 8b 88 e0 02 00 00 48 90 01 06 49 8b 87 90 01 04 48 90 01 06 49 8b 87 90 01 04 41 bb 90 01 04 4d 8b 4f 90 01 01 69 90 01 09 41 8b 89 90 00 } //01 00 
		$a_00_2 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //00 00  DllRegisterServer
	condition:
		any of ($a_*)
 
}
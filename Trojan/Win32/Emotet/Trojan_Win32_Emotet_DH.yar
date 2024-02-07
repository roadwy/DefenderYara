
rule Trojan_Win32_Emotet_DH{
	meta:
		description = "Trojan:Win32/Emotet.DH,SIGNATURE_TYPE_PEHSTR_EXT,04 00 02 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {7a 31 65 2e 62 6d 61 69 32 39 38 52 73 42 53 32 } //01 00  z1e.bmai298RsBS2
		$a_01_1 = {76 00 65 00 43 00 67 00 32 00 4a 00 33 00 73 00 77 00 41 00 2f 00 66 00 71 00 6a 00 50 00 } //01 00  veCg2J3swA/fqjP
		$a_01_2 = {2a 00 67 00 51 00 46 00 77 00 2f 00 5a 00 3e 00 38 00 58 00 79 00 3d 00 43 00 37 00 4a 00 35 00 42 00 78 00 4b 00 } //01 00  *gQFw/Z>8Xy=C7J5BxK
		$a_01_3 = {43 00 40 00 49 00 44 00 33 00 53 00 4c 00 4e 00 72 00 38 00 } //00 00  C@ID3SLNr8
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Emotet_DH_2{
	meta:
		description = "Trojan:Win32/Emotet.DH,SIGNATURE_TYPE_PEHSTR,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {65 72 68 65 72 6a 23 40 21 67 62 65 72 68 2e 70 64 62 } //01 00  erherj#@!gberh.pdb
		$a_01_1 = {7a 71 37 7a 77 65 67 61 5f 6a 66 2e 70 64 62 } //00 00  zq7zwega_jf.pdb
	condition:
		any of ($a_*)
 
}

rule Trojan_Win32_Amadey_GEE_MTB{
	meta:
		description = "Trojan:Win32/Amadey.GEE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {0f 43 ca 03 c1 3b f0 0f 84 90 01 04 8b 45 e8 8d 4d c4 6a 90 01 01 c7 45 90 01 05 c7 45 90 01 05 8a 04 30 32 06 88 45 ef 8d 45 ef 50 90 00 } //01 00 
		$a_01_1 = {41 6d 61 64 65 79 5c 52 65 6c 65 61 73 65 5c 41 6d 61 64 65 79 2e 70 64 62 } //00 00  Amadey\Release\Amadey.pdb
	condition:
		any of ($a_*)
 
}
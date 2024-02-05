
rule Trojan_Win32_ClipBanker_GNR_MTB{
	meta:
		description = "Trojan:Win32/ClipBanker.GNR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {2b c6 88 5c 24 32 88 5c 24 41 89 44 24 28 57 b1 4b bb 90 01 04 b8 90 01 04 2b de 2b c6 bf 90 01 04 b2 d0 2b fe 88 4c 24 38 88 4c 24 42 88 4c 24 47 c6 44 24 34 78 c6 44 24 35 61 88 54 24 3a c6 44 24 3e 66 c6 44 24 41 33 c6 44 24 43 2d c6 44 24 44 74 88 54 24 46 c6 44 24 40 af c6 44 24 39 62 90 00 } //01 00 
		$a_80_1 = {4a 65 6c 6c 79 62 65 61 6e 73 2e 65 78 65 } //Jellybeans.exe  00 00 
	condition:
		any of ($a_*)
 
}

rule Backdoor_WinNT_Turla_C_dha{
	meta:
		description = "Backdoor:WinNT/Turla.C!dha,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {4e 64 69 73 46 52 65 67 69 73 74 65 72 46 69 6c 74 65 72 44 72 69 76 65 72 } //01 00  NdisFRegisterFilterDriver
		$a_00_1 = {46 77 70 6d 43 61 6c 6c 6f 75 74 41 64 64 30 } //01 00  FwpmCalloutAdd0
		$a_00_2 = {5c 42 61 73 65 4e 61 6d 65 64 4f 62 6a 65 63 74 73 5c 7b 63 32 62 39 39 62 35 30 2d 35 62 66 32 2d 34 63 38 31 2d 39 30 64 33 2d 36 63 36 63 38 32 62 61 35 31 31 31 7d } //01 00  \BaseNamedObjects\{c2b99b50-5bf2-4c81-90d3-6c6c82ba5111}
		$a_02_3 = {48 8d 4c 24 40 33 d2 41 b8 04 01 00 00 e8 90 01 04 44 8b 5f 30 4c 8d 0d 90 01 04 4c 8d 05 90 01 04 48 8d 4c 24 40 ba 03 01 00 00 44 89 5c 24 20 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
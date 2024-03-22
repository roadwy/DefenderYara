
rule Trojan_BAT_EvilGDefByp_A_MTB{
	meta:
		description = "Trojan:BAT/EvilGDefByp.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,21 00 21 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 00 64 00 6d 00 69 00 6e 00 20 00 70 00 72 00 69 00 76 00 65 00 6c 00 65 00 67 00 69 00 65 00 73 00 3a 00 } //01 00  Admin privelegies:
		$a_01_1 = {53 00 74 00 61 00 72 00 74 00 69 00 6e 00 67 00 20 00 45 00 6c 00 65 00 76 00 61 00 74 00 69 00 6e 00 67 00 20 00 74 00 6f 00 20 00 53 00 59 00 53 00 54 00 45 00 4d 00 } //0a 00  Starting Elevating to SYSTEM
		$a_01_2 = {53 00 74 00 61 00 72 00 74 00 69 00 6e 00 67 00 20 00 57 00 44 00 20 00 44 00 69 00 73 00 61 00 62 00 6c 00 65 00 } //0a 00  Starting WD Disable
		$a_01_3 = {4d 00 73 00 4d 00 70 00 45 00 6e 00 67 00 } //01 00  MsMpEng
		$a_81_4 = {53 65 6c 65 63 74 20 2a 20 46 72 6f 6d 20 57 69 6e 33 32 5f 50 72 6f 63 65 73 73 20 57 68 65 72 65 20 50 72 6f 63 65 73 73 49 44 20 3d } //0a 00  Select * From Win32_Process Where ProcessID =
		$a_01_5 = {44 69 73 61 62 6c 65 20 57 44 5c 41 42 43 5c 41 42 43 5c 6f 62 6a 5c 44 65 62 75 67 5c 41 42 43 2e 70 64 62 } //00 00  Disable WD\ABC\ABC\obj\Debug\ABC.pdb
	condition:
		any of ($a_*)
 
}
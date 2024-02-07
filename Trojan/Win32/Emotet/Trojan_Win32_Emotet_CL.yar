
rule Trojan_Win32_Emotet_CL{
	meta:
		description = "Trojan:Win32/Emotet.CL,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {56 4c 41 48 5f 32 5f 61 63 72 6a 6f 2e 70 64 62 } //01 00  VLAH_2_acrjo.pdb
		$a_01_1 = {25 34 43 71 53 6a 4d 70 6b 49 26 } //01 00  %4CqSjMpkI&
		$a_00_2 = {4b 00 65 00 79 00 20 00 22 00 25 00 73 00 22 00 20 00 6e 00 6f 00 74 00 20 00 66 00 6f 00 75 00 6e 00 64 00 25 00 67 00 6f 00 43 00 6f 00 6c 00 4d 00 6f 00 76 00 69 00 6e 00 67 00 20 00 69 00 73 00 20 00 6e 00 6f 00 74 00 20 00 61 00 20 00 73 00 75 00 70 00 70 00 6f 00 72 00 74 00 65 00 64 00 20 00 6f 00 70 00 74 00 69 00 6f 00 6e 00 25 00 4b 00 65 00 79 00 20 00 6d 00 61 00 79 00 20 00 6e 00 6f 00 74 00 20 00 63 00 6f 00 6e 00 74 00 61 00 69 00 6e 00 20 00 65 00 71 00 75 00 61 00 6c 00 73 00 20 00 73 00 69 00 67 00 6e 00 20 00 28 00 22 00 3d 00 22 00 29 00 } //00 00  Key "%s" not found%goColMoving is not a supported option%Key may not contain equals sign ("=")
	condition:
		any of ($a_*)
 
}
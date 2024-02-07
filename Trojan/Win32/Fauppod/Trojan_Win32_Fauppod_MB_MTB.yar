
rule Trojan_Win32_Fauppod_MB_MTB{
	meta:
		description = "Trojan:Win32/Fauppod.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {44 64 63 74 66 76 48 75 62 68 6e 6a } //02 00  DdctfvHubhnj
		$a_01_1 = {4f 6a 6e 68 54 66 63 64 } //02 00  OjnhTfcd
		$a_01_2 = {45 66 76 68 50 6a 6e 68 6a 62 } //01 00  EfvhPjnhjb
		$a_01_3 = {57 61 69 74 46 6f 72 53 69 6e 67 6c 65 4f 62 6a 65 63 74 } //00 00  WaitForSingleObject
	condition:
		any of ($a_*)
 
}
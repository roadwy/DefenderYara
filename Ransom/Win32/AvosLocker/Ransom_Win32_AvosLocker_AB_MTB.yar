
rule Ransom_Win32_AvosLocker_AB_MTB{
	meta:
		description = "Ransom:Win32/AvosLocker.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {83 f9 07 73 90 01 01 8a 84 0d 90 01 04 32 c2 88 85 90 01 04 88 84 0d 90 01 04 41 89 8d 90 01 04 8a 95 90 01 04 eb 90 00 } //01 00 
		$a_01_1 = {42 72 75 74 65 66 6f 72 63 65 20 53 4d 42 20 66 6f 72 20 6c 6f 67 69 63 61 6c 20 64 72 69 76 65 73 } //00 00 
	condition:
		any of ($a_*)
 
}
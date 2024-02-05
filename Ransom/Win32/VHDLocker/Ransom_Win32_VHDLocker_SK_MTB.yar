
rule Ransom_Win32_VHDLocker_SK_MTB{
	meta:
		description = "Ransom:Win32/VHDLocker.SK!MTB,SIGNATURE_TYPE_PEHSTR,19 00 14 00 03 00 00 0a 00 "
		
	strings :
		$a_01_0 = {48 00 6f 00 77 00 54 00 6f 00 44 00 65 00 63 00 72 00 79 00 70 00 74 00 2e 00 74 00 78 00 74 00 } //0a 00 
		$a_01_1 = {41 00 45 00 45 00 41 00 45 00 45 00 20 00 53 00 45 00 54 00 } //05 00 
		$a_01_2 = {63 00 3a 00 2f 00 64 00 61 00 74 00 61 00 2f 00 70 00 72 00 6a 00 2f 00 74 00 65 00 73 00 74 00 } //00 00 
	condition:
		any of ($a_*)
 
}

rule Ransom_Win32_LockerGoga{
	meta:
		description = "Ransom:Win32/LockerGoga,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 3d 00 2e 00 6c 00 6f 00 63 00 6b 00 65 00 64 00 00 00 5c 00 3f 00 3f 00 5c 00 5c 00 00 00 20 46 41 49 4c 45 44 } //01 00 
		$a_01_1 = {52 45 41 44 4d 45 5f 4c 4f 43 4b 45 44 2e 74 78 74 00 } //00 00 
	condition:
		any of ($a_*)
 
}
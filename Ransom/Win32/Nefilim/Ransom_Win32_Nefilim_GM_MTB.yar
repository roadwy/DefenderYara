
rule Ransom_Win32_Nefilim_GM_MTB{
	meta:
		description = "Ransom:Win32/Nefilim.GM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {8a 1c 03 8b 90 02 10 8a 14 01 8a 08 88 5d 90 02 15 8a 1c 03 90 02 64 32 93 90 02 30 8a 1c 33 32 da 90 02 30 32 d1 88 50 90 01 01 8a 0e 32 4d 90 02 10 88 4e 90 02 25 32 4d 90 02 10 88 0f 90 00 } //01 00 
		$a_00_1 = {2f 63 20 57 6d 49 63 20 53 68 61 44 6f 77 63 6f 50 59 20 64 65 6c 45 74 65 } //00 00 
	condition:
		any of ($a_*)
 
}
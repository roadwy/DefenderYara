
rule Ransom_Win32_Cobra_AB_MTB{
	meta:
		description = "Ransom:Win32/Cobra.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {2e 43 6f 62 72 61 } //01 00  .Cobra
		$a_81_1 = {72 61 6e 73 6f 6d 77 61 72 65 } //01 00  ransomware
		$a_81_2 = {41 6c 6c 20 79 6f 75 72 20 69 6d 70 6f 72 74 61 6e 74 20 66 69 6c 65 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 21 } //01 00  All your important files are encrypted!
		$a_81_3 = {43 6f 62 72 61 5f 4c 6f 63 6b 65 72 } //00 00  Cobra_Locker
		$a_00_4 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}
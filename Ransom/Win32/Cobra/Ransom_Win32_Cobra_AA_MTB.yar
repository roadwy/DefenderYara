
rule Ransom_Win32_Cobra_AA_MTB{
	meta:
		description = "Ransom:Win32/Cobra.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 00 43 00 6f 00 62 00 72 00 61 00 } //01 00  .Cobra
		$a_81_1 = {52 61 6e 73 6f 6d 77 61 72 65 } //01 00  Ransomware
		$a_01_2 = {59 00 6f 00 75 00 72 00 20 00 68 00 61 00 76 00 65 00 20 00 62 00 65 00 65 00 6e 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 21 00 } //01 00  Your have been encrypted!
		$a_01_3 = {59 00 6f 00 75 00 72 00 20 00 66 00 69 00 6c 00 65 00 73 00 20 00 68 00 61 00 76 00 65 00 20 00 62 00 65 00 65 00 6e 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 21 00 } //01 00  Your files have been encrypted!
		$a_01_4 = {43 00 6f 00 62 00 72 00 61 00 5f 00 4c 00 6f 00 63 00 6b 00 65 00 72 00 } //00 00  Cobra_Locker
		$a_00_5 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}
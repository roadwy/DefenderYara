
rule Ransom_MSIL_EnryLocker_PAA_MTB{
	meta:
		description = "Ransom:MSIL/EnryLocker.PAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {52 61 6e 73 6f 6d 65 57 61 72 65 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //01 00  RansomeWare.Properties.Resources.resources
		$a_01_1 = {52 61 6e 73 6f 6d 65 57 61 72 65 2e 70 64 62 } //01 00  RansomeWare.pdb
		$a_01_2 = {59 00 6f 00 75 00 72 00 20 00 66 00 69 00 6c 00 65 00 73 00 20 00 68 00 61 00 76 00 65 00 20 00 62 00 65 00 65 00 6e 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 } //01 00  Your files have been encrypted
		$a_01_3 = {2e 00 68 00 65 00 6e 00 72 00 79 00 } //00 00  .henry
	condition:
		any of ($a_*)
 
}
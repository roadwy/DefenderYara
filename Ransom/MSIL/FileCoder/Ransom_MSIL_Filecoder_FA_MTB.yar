
rule Ransom_MSIL_Filecoder_FA_MTB{
	meta:
		description = "Ransom:MSIL/Filecoder.FA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {2e 77 6e 63 72 79 } //01 00  .wncry
		$a_81_1 = {2e 5a 49 45 42 46 5f 34 35 36 31 64 72 67 66 } //01 00  .ZIEBF_4561drgf
		$a_81_2 = {74 65 6d 70 31 30 2e 70 6e 67 } //01 00  temp10.png
		$a_81_3 = {42 36 35 34 31 32 36 35 31 32 33 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //01 00  B6541265123.Properties.Resources
		$a_81_4 = {42 36 35 34 31 32 36 35 31 32 33 2e 65 78 65 } //00 00  B6541265123.exe
	condition:
		any of ($a_*)
 
}
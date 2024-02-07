
rule Ransom_MSIL_HiddenTear_PH_MTB{
	meta:
		description = "Ransom:MSIL/HiddenTear.PH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 00 6c 00 6f 00 63 00 6b 00 79 00 } //01 00  .locky
		$a_01_1 = {72 00 65 00 61 00 64 00 6d 00 65 00 2d 00 6c 00 6f 00 63 00 6b 00 79 00 2e 00 74 00 78 00 74 00 } //01 00  readme-locky.txt
		$a_01_2 = {5c 6c 6f 63 6b 79 2e 70 64 62 } //00 00  \locky.pdb
	condition:
		any of ($a_*)
 
}

rule Ransom_MSIL_FileCoder_SG_MTB{
	meta:
		description = "Ransom:MSIL/FileCoder.SG!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {24 31 30 66 31 66 30 33 37 2d 66 65 64 39 2d 34 64 61 32 2d 38 63 36 62 2d 37 35 62 64 64 33 32 34 62 38 66 39 } //01 00  $10f1f037-fed9-4da2-8c6b-75bdd324b8f9
		$a_01_1 = {5c 63 72 79 70 74 6f 62 72 69 63 6b 2e 70 64 62 } //00 00  \cryptobrick.pdb
	condition:
		any of ($a_*)
 
}
rule Ransom_MSIL_FileCoder_SG_MTB_2{
	meta:
		description = "Ransom:MSIL/FileCoder.SG!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {4e 69 74 72 6f 52 61 6e 73 6f 6d 77 61 72 65 2e 52 65 73 6f 75 72 63 65 73 2e 77 6c 2e 70 6e 67 } //02 00  NitroRansomware.Resources.wl.png
		$a_01_1 = {24 64 35 65 38 37 34 33 39 2d 32 31 65 36 2d 34 35 36 37 2d 61 38 37 37 2d 36 61 64 39 62 65 65 30 30 64 63 39 } //00 00  $d5e87439-21e6-4567-a877-6ad9bee00dc9
	condition:
		any of ($a_*)
 
}
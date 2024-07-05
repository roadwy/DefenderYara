
rule Trojan_BAT_Remcos_SKI_MTB{
	meta:
		description = "Trojan:BAT/Remcos.SKI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {43 3a 5c 55 73 65 72 73 5c 41 64 6d 69 6e 69 73 74 72 61 74 6f 72 5c 44 65 73 6b 74 6f 70 5c 4f 75 74 70 75 74 73 5c 59 67 5a 42 72 73 4c 4e 65 2e 70 64 62 } //01 00  C:\Users\Administrator\Desktop\Outputs\YgZBrsLNe.pdb
		$a_81_1 = {32 6d 47 4c 4c 50 75 63 56 58 39 65 59 51 65 47 77 69 4e 52 75 58 38 34 4a 50 58 33 54 32 46 76 4a 6f 75 74 62 79 6c 7a 33 49 67 5a 44 30 74 53 33 41 30 79 4a 7a 57 65 } //01 00  2mGLLPucVX9eYQeGwiNRuX84JPX3T2FvJoutbylz3IgZD0tS3A0yJzWe
		$a_81_2 = {4f 78 79 50 6c 6f 74 74 69 6e 67 2e 45 57 47 69 62 72 61 6c 74 61 72 } //01 00  OxyPlotting.EWGibraltar
		$a_81_3 = {42 75 6e 64 6c 65 53 68 61 72 70 } //00 00  BundleSharp
	condition:
		any of ($a_*)
 
}
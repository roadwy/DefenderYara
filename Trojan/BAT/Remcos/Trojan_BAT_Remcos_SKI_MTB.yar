
rule Trojan_BAT_Remcos_SKI_MTB{
	meta:
		description = "Trojan:BAT/Remcos.SKI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {00 02 03 06 07 04 28 32 00 00 06 00 00 07 17 58 0b 07 02 28 30 00 00 06 2f 0b 03 6f 96 00 00 0a 04 fe 04 2b 01 16 0c 08 2d d6 } //1
		$a_81_1 = {24 35 38 65 64 64 35 33 36 2d 31 61 63 61 2d 34 33 34 36 2d 39 37 63 65 2d 64 36 30 36 62 33 31 31 31 66 35 31 } //1 $58edd536-1aca-4346-97ce-d606b3111f51
	condition:
		((#a_00_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}
rule Trojan_BAT_Remcos_SKI_MTB_2{
	meta:
		description = "Trojan:BAT/Remcos.SKI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {43 3a 5c 55 73 65 72 73 5c 41 64 6d 69 6e 69 73 74 72 61 74 6f 72 5c 44 65 73 6b 74 6f 70 5c 4f 75 74 70 75 74 73 5c 59 67 5a 42 72 73 4c 4e 65 2e 70 64 62 } //1 C:\Users\Administrator\Desktop\Outputs\YgZBrsLNe.pdb
		$a_81_1 = {32 6d 47 4c 4c 50 75 63 56 58 39 65 59 51 65 47 77 69 4e 52 75 58 38 34 4a 50 58 33 54 32 46 76 4a 6f 75 74 62 79 6c 7a 33 49 67 5a 44 30 74 53 33 41 30 79 4a 7a 57 65 } //1 2mGLLPucVX9eYQeGwiNRuX84JPX3T2FvJoutbylz3IgZD0tS3A0yJzWe
		$a_81_2 = {4f 78 79 50 6c 6f 74 74 69 6e 67 2e 45 57 47 69 62 72 61 6c 74 61 72 } //1 OxyPlotting.EWGibraltar
		$a_81_3 = {42 75 6e 64 6c 65 53 68 61 72 70 } //1 BundleSharp
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}
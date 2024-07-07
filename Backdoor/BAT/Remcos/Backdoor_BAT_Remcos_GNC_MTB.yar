
rule Backdoor_BAT_Remcos_GNC_MTB{
	meta:
		description = "Backdoor:BAT/Remcos.GNC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {63 37 31 30 37 36 39 37 34 31 37 37 32 63 66 65 31 34 63 63 65 65 32 36 34 62 39 37 31 30 30 61 65 } //1 c710769741772cfe14ccee264b97100ae
		$a_01_1 = {63 63 34 61 66 62 37 30 64 30 65 62 62 61 61 33 64 34 39 30 64 30 65 63 31 64 61 31 36 62 33 30 63 } //1 cc4afb70d0ebbaa3d490d0ec1da16b30c
		$a_80_2 = {51 6b 68 49 53 45 63 32 4e 69 55 3d } //QkhISEc2NiU=  1
		$a_80_3 = {51 6b 68 49 53 45 63 32 4e 69 51 3d } //QkhISEc2NiQ=  1
		$a_80_4 = {42 48 48 48 47 36 36 } //BHHHG66  1
		$a_01_5 = {44 6f 63 75 6d 65 6e 74 73 5c 43 72 79 70 74 6f 4f 62 66 75 73 63 61 74 6f 72 5f 4f 75 74 70 75 74 5c 42 48 48 48 47 36 36 2e 70 64 62 } //1 Documents\CryptoObfuscator_Output\BHHHG66.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}
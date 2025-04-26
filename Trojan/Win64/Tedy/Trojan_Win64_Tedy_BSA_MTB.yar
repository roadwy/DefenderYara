
rule Trojan_Win64_Tedy_BSA_MTB{
	meta:
		description = "Trojan:Win64/Tedy.BSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_80_0 = {43 75 7a 50 50 2e 65 78 65 } //CuzPP.exe  10
		$a_80_1 = {47 6f 6f 6e 45 79 65 2e 65 78 65 } //GoonEye.exe  1
		$a_80_2 = {5c 52 65 6c 65 61 73 65 5c 43 75 7a 50 50 2e 70 64 62 } //\Release\CuzPP.pdb  1
	condition:
		((#a_80_0  & 1)*10+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=12
 
}
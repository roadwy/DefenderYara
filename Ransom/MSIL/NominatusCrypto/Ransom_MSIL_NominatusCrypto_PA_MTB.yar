
rule Ransom_MSIL_NominatusCrypto_PA_MTB{
	meta:
		description = "Ransom:MSIL/NominatusCrypto.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 00 65 00 78 00 65 00 20 00 3e 00 3e 00 61 00 75 00 74 00 6f 00 72 00 75 00 6e 00 2e 00 69 00 6e 00 66 00 } //01 00  .exe >>autorun.inf
		$a_01_1 = {76 00 73 00 73 00 61 00 64 00 6d 00 69 00 6e 00 20 00 64 00 65 00 6c 00 65 00 74 00 65 00 20 00 73 00 68 00 61 00 64 00 6f 00 77 00 73 00 20 00 2f 00 61 00 6c 00 6c 00 20 00 2f 00 71 00 75 00 69 00 65 00 74 00 20 00 26 00 26 00 20 00 77 00 6d 00 69 00 63 00 20 00 73 00 68 00 61 00 64 00 6f 00 77 00 63 00 6f 00 70 00 79 00 20 00 64 00 65 00 6c 00 65 00 74 00 65 00 } //01 00  vssadmin delete shadows /all /quiet && wmic shadowcopy delete
		$a_01_2 = {74 00 61 00 73 00 6b 00 6b 00 69 00 6c 00 6c 00 20 00 2f 00 69 00 6d 00 20 00 77 00 69 00 6e 00 69 00 6e 00 69 00 74 00 2e 00 65 00 78 00 65 00 20 00 2f 00 66 00 } //01 00  taskkill /im wininit.exe /f
		$a_01_3 = {5c 45 76 69 6c 4e 6f 6d 69 6e 61 74 75 73 43 72 79 70 74 6f 2e 70 64 62 } //00 00  \EvilNominatusCrypto.pdb
	condition:
		any of ($a_*)
 
}
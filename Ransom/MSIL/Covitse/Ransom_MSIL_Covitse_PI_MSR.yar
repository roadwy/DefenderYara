
rule Ransom_MSIL_Covitse_PI_MSR{
	meta:
		description = "Ransom:MSIL/Covitse.PI!MSR,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {5b 00 43 00 4f 00 56 00 49 00 44 00 2d 00 31 00 39 00 20 00 52 00 41 00 4e 00 53 00 4f 00 4d 00 57 00 41 00 52 00 45 00 5d 00 } //01 00  [COVID-19 RANSOMWARE]
		$a_01_1 = {79 00 6f 00 75 00 72 00 20 00 62 00 65 00 65 00 6e 00 20 00 69 00 6e 00 66 00 65 00 63 00 74 00 65 00 64 00 20 00 77 00 69 00 74 00 68 00 20 00 4c 00 61 00 6e 00 73 00 6f 00 6d 00 20 00 62 00 79 00 20 00 43 00 4f 00 56 00 49 00 44 00 2d 00 31 00 39 00 20 00 52 00 61 00 6e 00 73 00 6f 00 6d 00 77 00 61 00 72 00 65 00 2e 00 } //01 00  your been infected with Lansom by COVID-19 Ransomware.
		$a_01_2 = {5c 43 4f 56 49 44 2d 31 39 2e 70 64 62 } //00 00  \COVID-19.pdb
	condition:
		any of ($a_*)
 
}
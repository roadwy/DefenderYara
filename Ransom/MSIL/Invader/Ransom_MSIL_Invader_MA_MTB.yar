
rule Ransom_MSIL_Invader_MA_MTB{
	meta:
		description = "Ransom:MSIL/Invader.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {75 6c 75 42 67 58 74 57 67 72 4c 31 4a 35 31 76 72 4e 2e 56 45 34 52 6b 44 6a 68 35 4e 4a 51 49 69 66 56 52 35 } //02 00  uluBgXtWgrL1J51vrN.VE4RkDjh5NJQIifVR5
		$a_01_1 = {6a 68 73 49 6e 32 49 43 69 72 4e 35 62 45 5a 4f 34 71 2e 39 5a 39 4a 47 59 33 34 36 38 33 48 51 6e 37 66 6f 6d } //01 00  jhsIn2ICirN5bEZO4q.9Z9JGY34683HQn7fom
		$a_01_2 = {37 37 33 38 64 61 37 32 2d 31 31 33 33 2d 34 61 63 66 2d 61 36 62 32 2d 66 33 35 31 32 62 61 65 39 62 32 61 } //00 00  7738da72-1133-4acf-a6b2-f3512bae9b2a
	condition:
		any of ($a_*)
 
}
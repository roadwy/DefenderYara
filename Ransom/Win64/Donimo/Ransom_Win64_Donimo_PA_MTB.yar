
rule Ransom_Win64_Donimo_PA_MTB{
	meta:
		description = "Ransom:Win64/Donimo.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {49 63 c1 4c 8d 1d 90 01 04 42 8a 04 18 32 04 11 88 02 41 8d 41 01 25 0f 00 00 80 7d 90 01 01 ff c8 83 c8 f0 ff c0 48 ff c2 44 8b c8 49 ff ca 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
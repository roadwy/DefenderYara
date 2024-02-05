
rule Ransom_Win64_NightSky_PC_MTB{
	meta:
		description = "Ransom:Win64/NightSky.PC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_80_0 = {2e 6e 69 67 68 74 73 6b 79 } //.nightsky  01 00 
		$a_80_1 = {5c 4e 69 67 68 74 53 6b 79 52 65 61 64 4d 65 2e 68 74 61 } //\NightSkyReadMe.hta  00 00 
	condition:
		any of ($a_*)
 
}
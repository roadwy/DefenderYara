
rule PWS_Win32_AgentTesla_YB_MTB{
	meta:
		description = "PWS:Win32/AgentTesla.YB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 44 65 62 75 67 5c 49 45 4c 69 62 72 61 72 79 2e 70 64 62 } //01 00  \Debug\IELibrary.pdb
		$a_01_1 = {24 38 33 30 31 38 35 39 35 2d 33 66 38 61 2d 34 65 37 31 2d 39 34 62 32 2d 38 65 34 31 61 36 31 65 64 37 36 33 } //00 00  $83018595-3f8a-4e71-94b2-8e41a61ed763
	condition:
		any of ($a_*)
 
}
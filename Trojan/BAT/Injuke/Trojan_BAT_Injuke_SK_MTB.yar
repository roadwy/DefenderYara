
rule Trojan_BAT_Injuke_SK_MTB{
	meta:
		description = "Trojan:BAT/Injuke.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {45 69 6b 63 72 2e 65 78 65 } //01 00  Eikcr.exe
		$a_81_1 = {45 69 6b 63 72 2e 46 61 63 74 6f 72 69 65 73 } //01 00  Eikcr.Factories
		$a_81_2 = {42 61 71 65 74 69 77 66 64 70 65 2e 50 72 6f 70 65 72 74 69 65 73 } //01 00  Baqetiwfdpe.Properties
		$a_81_3 = {7b 37 38 30 39 37 30 34 34 2d 38 38 30 38 2d 34 36 30 64 2d 39 66 32 64 2d 64 64 37 63 39 61 35 30 64 32 39 32 7d } //00 00  {78097044-8808-460d-9f2d-dd7c9a50d292}
	condition:
		any of ($a_*)
 
}
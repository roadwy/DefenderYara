
rule Trojan_Win32_Guloader_BP_MTB{
	meta:
		description = "Trojan:Win32/Guloader.BP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 72 6f 75 74 6f 6e 5c 49 6e 64 76 69 6e 64 69 6e 67 65 72 6e 65 73 2e 50 61 72 } //01 00  Crouton\Indvindingernes.Par
		$a_01_1 = {48 76 69 64 65 76 61 72 65 72 5c 46 65 6c 69 63 65 5c 51 75 61 74 75 6f 72 5c 43 61 72 62 6f 6e 61 74 61 74 69 6f 6e 2e 73 68 75 } //01 00  Hvidevarer\Felice\Quatuor\Carbonatation.shu
		$a_01_2 = {53 6f 66 74 77 61 72 65 5c 45 78 70 6f 72 74 65 72 73 5c 53 63 79 62 61 6c 61 31 37 38 } //01 00  Software\Exporters\Scybala178
		$a_01_3 = {4f 76 65 72 73 74 72 6d 6d 65 6e 64 65 73 32 35 30 5c 45 6b 73 6b 6c 75 64 65 72 5c 43 6f 6f 63 6f 6f 2e 53 6f 72 } //00 00  Overstrmmendes250\Ekskluder\Coocoo.Sor
	condition:
		any of ($a_*)
 
}
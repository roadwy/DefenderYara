
rule Trojan_BAT_SmokeLoader_NEA_MTB{
	meta:
		description = "Trojan:BAT/SmokeLoader.NEA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 6f 72 74 61 62 6c 65 41 70 70 73 2e 63 6f 6d } //01 00  PortableApps.com
		$a_01_1 = {44 4f 53 42 6f 78 20 50 6f 72 74 61 62 6c 65 } //01 00  DOSBox Portable
		$a_01_2 = {32 2e 32 2e 31 2e 30 } //01 00  2.2.1.0
		$a_01_3 = {52 61 72 65 20 49 64 65 61 73 } //01 00  Rare Ideas
		$a_01_4 = {42 71 69 61 69 39 68 50 6a } //00 00  Bqiai9hPj
	condition:
		any of ($a_*)
 
}

rule Trojan_Win64_LatortugaGoPEloader_LK_MTB{
	meta:
		description = "Trojan:Win64/LatortugaGoPEloader.LK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {67 69 74 68 75 62 2e 63 6f 6d 2f 6c 61 74 6f 72 74 75 67 61 37 31 2f 47 6f 50 65 4c 6f 61 64 65 72 2f 70 6b 67 2f 70 65 6c 6f 61 64 65 72 } //01 00  github.com/latortuga71/GoPeLoader/pkg/peloader
		$a_01_1 = {47 6f 20 62 75 69 6c 64 20 49 44 3a } //00 00  Go build ID:
	condition:
		any of ($a_*)
 
}
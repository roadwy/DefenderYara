
rule TrojanDownloader_O97M_Gamaredon_P_MSR{
	meta:
		description = "TrojanDownloader:O97M/Gamaredon.P!MSR,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {73 6f 6c 6f 64 2e 62 6f 75 6e 63 65 6d 65 2e 6e 65 74 } //1 solod.bounceme.net
		$a_01_1 = {2e 52 65 67 52 65 61 64 28 22 48 4b 43 55 5c 4b 65 79 62 6f 61 72 64 20 4c 61 79 6f 75 74 5c 50 72 65 6c 6f 61 64 } //1 .RegRead("HKCU\Keyboard Layout\Preload
		$a_01_2 = {74 65 6c 65 6d 65 74 72 69 79 61 2e 70 68 70 } //1 telemetriya.php
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
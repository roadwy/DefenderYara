
rule TrojanDownloader_O97M_Qakbot_PDK_MTB{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.PDK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {62 6f 6e 67 6f 61 6e 64 72 6f 69 64 61 70 6b 2e 63 6f 6d 2f 63 43 43 61 6e 69 54 4f 6a 48 2f 45 68 72 6e 66 2e 70 6e 67 } //01 00  bongoandroidapk.com/cCCaniTOjH/Ehrnf.png
		$a_01_1 = {6e 69 74 79 61 68 61 6e 64 69 63 72 61 66 74 73 2e 63 6f 6d 2f 6a 6e 34 36 6f 41 46 72 54 54 70 76 2f 45 68 72 6e 66 2e 70 6e 67 } //01 00  nityahandicrafts.com/jn46oAFrTTpv/Ehrnf.png
		$a_01_2 = {64 65 65 70 2d 63 75 72 65 2e 63 6f 6d 2f 51 42 6a 44 65 67 69 50 49 61 2f 45 68 72 6e 66 2e 70 6e 67 } //00 00  deep-cure.com/QBjDegiPIa/Ehrnf.png
	condition:
		any of ($a_*)
 
}
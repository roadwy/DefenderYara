
rule TrojanDropper_BAT_Dyzoone_A{
	meta:
		description = "TrojanDropper:BAT/Dyzoone.A,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 45 50 52 4f 4b 2e 72 65 73 6f 75 72 63 65 73 } //01 00  .EPROK.resources
		$a_01_1 = {52 65 73 6f 75 72 63 65 57 72 69 74 65 72 } //01 00  ResourceWriter
		$a_01_2 = {53 79 73 74 65 6d 2e 53 65 63 75 72 69 74 79 2e 43 72 79 70 74 6f 67 72 61 70 68 79 2e 58 35 30 39 43 65 72 74 69 66 69 63 61 74 65 73 } //01 00  System.Security.Cryptography.X509Certificates
		$a_01_3 = {45 6e 63 6f 64 65 72 46 61 6c 6c 62 61 63 6b } //02 00  EncoderFallback
		$a_01_4 = {55 70 6c 6f 61 64 73 57 65 6c 6c 63 6f 6e 6e 65 63 00 } //02 00  灕潬摡坳汥捬湯敮c
		$a_01_5 = {4b 6f 71 79 72 69 67 68 74 } //00 00  Koqyright
	condition:
		any of ($a_*)
 
}

rule Trojan_BAT_SnakeKeyLogger_RDG_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeyLogger.RDG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {54 69 6d 65 64 69 78 20 53 65 72 65 6e 74 79 } //01 00  Timedix Serenty
		$a_01_1 = {45 00 72 00 62 00 6e 00 4b 00 68 00 4f 00 42 00 69 00 57 00 54 00 53 00 52 00 4b 00 45 00 2e 00 45 00 72 00 62 00 6e 00 4b 00 68 00 4f 00 42 00 69 00 57 00 54 00 53 00 52 00 4b 00 45 00 } //01 00  ErbnKhOBiWTSRKE.ErbnKhOBiWTSRKE
		$a_01_2 = {68 00 57 00 51 00 48 00 6c 00 53 00 4f 00 78 00 48 00 51 00 4b 00 61 00 4e 00 44 00 76 00 } //01 00  hWQHlSOxHQKaNDv
		$a_01_3 = {61 00 73 00 65 00 6c 00 72 00 69 00 61 00 73 00 33 00 38 00 34 00 39 00 30 00 61 00 33 00 32 00 } //00 00  aselrias38490a32
	condition:
		any of ($a_*)
 
}
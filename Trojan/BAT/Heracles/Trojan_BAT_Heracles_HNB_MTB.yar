
rule Trojan_BAT_Heracles_HNB_MTB{
	meta:
		description = "Trojan:BAT/Heracles.HNB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {00 00 00 6e 74 64 6c 6c 2e 64 6c 6c 00 00 00 00 00 00 00 4e 74 43 72 65 61 74 65 54 68 72 65 61 64 45 78 00 00 00 00 00 00 00 00 } //01 00 
		$a_03_1 = {4b 33 32 45 6e 75 6d 50 72 6f 63 65 73 73 65 73 90 02 04 52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 90 02 04 4b 33 32 45 6e 75 6d 50 72 6f 63 65 73 73 4d 6f 64 75 6c 65 73 90 00 } //02 00 
		$a_01_2 = {48 8d ac 24 b8 fe ff ff 48 81 ec 48 02 00 00 bb 01 00 00 00 45 33 f6 89 9d a8 01 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}
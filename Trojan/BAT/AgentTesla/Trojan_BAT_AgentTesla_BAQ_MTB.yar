
rule Trojan_BAT_AgentTesla_BAQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BAQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 02 00 "
		
	strings :
		$a_03_0 = {16 2b 34 8e 69 17 2d 32 26 26 26 1d 2c 02 07 0c 16 2d dc de 55 28 90 01 01 00 00 0a 2b d5 28 90 01 01 00 00 06 2b d5 6f 90 01 01 00 00 0a 2b d0 28 90 01 01 00 00 0a 2b cb 0b 2b ca 07 2b c9 07 2b c9 28 90 01 01 00 00 0a 2b ca 90 00 } //01 00 
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_01_2 = {52 65 76 65 72 73 65 } //01 00  Reverse
		$a_01_3 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //00 00  DownloadData
	condition:
		any of ($a_*)
 
}

rule Trojan_BAT_Filecoder_AQS_MTB{
	meta:
		description = "Trojan:BAT/Filecoder.AQS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {0a 0c 07 08 16 08 8e 69 6f 90 01 03 0a 0d 03 09 28 90 00 } //01 00 
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00 
		$a_01_2 = {4e 00 6f 00 6d 00 69 00 6e 00 61 00 74 00 75 00 73 00 43 00 72 00 79 00 70 00 74 00 } //00 00 
	condition:
		any of ($a_*)
 
}
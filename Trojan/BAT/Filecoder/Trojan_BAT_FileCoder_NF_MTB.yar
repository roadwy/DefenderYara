
rule Trojan_BAT_FileCoder_NF_MTB{
	meta:
		description = "Trojan:BAT/FileCoder.NF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {02 03 17 28 90 01 01 00 00 06 02 02 04 28 90 01 01 00 00 06 16 28 90 01 01 00 00 06 28 90 01 01 00 00 06 16 28 90 01 01 00 00 06 0b 90 00 } //01 00 
		$a_01_1 = {4f 6e 79 78 4c 6f 63 6b 65 72 } //00 00  OnyxLocker
	condition:
		any of ($a_*)
 
}
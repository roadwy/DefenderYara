
rule Trojan_BAT_RedLine_NRC_MTB{
	meta:
		description = "Trojan:BAT/RedLine.NRC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 05 00 "
		
	strings :
		$a_03_0 = {28 42 00 00 06 13 08 11 14 20 90 01 03 5d 5a 20 90 01 03 7a 61 38 90 01 03 ff 23 90 01 07 40 23 90 01 07 40 28 90 01 03 06 58 28 90 01 03 06 8d 90 01 03 01 25 16 13 0f 1f fc 20 90 01 03 17 20 90 01 03 63 61 20 90 01 03 74 33 0a 90 00 } //01 00 
		$a_01_1 = {4e 74 57 72 69 74 65 56 69 72 74 75 61 6c 4d 65 6d 6f 72 79 } //01 00  NtWriteVirtualMemory
		$a_01_2 = {50 72 6f 30 69 6e 63 65 } //00 00  Pro0ince
	condition:
		any of ($a_*)
 
}
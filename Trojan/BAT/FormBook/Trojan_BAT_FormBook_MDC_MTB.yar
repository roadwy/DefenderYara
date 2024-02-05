
rule Trojan_BAT_FormBook_MDC_MTB{
	meta:
		description = "Trojan:BAT/FormBook.MDC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {1f 16 58 0c 2b 18 00 7e 17 00 00 04 07 08 20 00 01 00 00 28 90 01 03 06 0b 00 08 15 58 0c 08 16 fe 04 16 fe 01 0d 09 2d dd 90 00 } //01 00 
		$a_01_1 = {43 00 6f 00 64 00 2e 00 53 00 70 00 6f 00 6e 00 64 00 65 00 2e 00 55 00 69 00 74 00 } //00 00 
	condition:
		any of ($a_*)
 
}
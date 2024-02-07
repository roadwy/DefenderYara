
rule Trojan_BAT_AsyncRat_CXFW_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.CXFW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {06 07 91 0d 06 07 06 08 91 9c 06 08 09 9c 07 17 58 0b 08 17 59 0c 07 08 32 e6 } //01 00 
		$a_01_1 = {39 75 62 6d 46 6a 49 47 31 68 63 6d 64 76 63 6e 41 67 63 32 6c 6f 56 43 48 4e 54 41 47 34 49 63 } //00 00  9ubmFjIG1hcmdvcnAgc2loVCHNTAG4Ic
	condition:
		any of ($a_*)
 
}
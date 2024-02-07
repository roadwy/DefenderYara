
rule Backdoor_BAT_Bladabindi_SPL_MTB{
	meta:
		description = "Backdoor:BAT/Bladabindi.SPL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 03 00 "
		
	strings :
		$a_03_0 = {06 16 fe 02 06 19 fe 04 5f 0b 07 2c 08 17 28 90 01 03 0a 00 00 00 06 1a fe 01 0c 08 2c 08 28 90 01 03 06 00 2b 09 00 06 17 d6 0a 06 1b 31 d1 90 00 } //01 00 
		$a_81_1 = {34 53 79 73 74 65 6d 2e 57 65 62 2e 53 65 72 76 69 63 65 73 2e 50 72 6f 74 6f 63 6f 6c 73 2e 53 6f 61 70 48 74 74 70 43 6c 69 65 6e 74 50 72 6f 74 6f 63 6f 6c } //00 00  4System.Web.Services.Protocols.SoapHttpClientProtocol
	condition:
		any of ($a_*)
 
}

rule Trojan_BAT_StormKitty_RD_MTB{
	meta:
		description = "Trojan:BAT/StormKitty.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 00 2f 00 31 00 39 00 35 00 2e 00 31 00 37 00 38 00 2e 00 31 00 32 00 30 00 2e 00 32 00 33 00 30 00 2f 00 66 00 69 00 6c 00 65 00 2f 00 } //01 00  //195.178.120.230/file/
		$a_03_1 = {07 20 80 00 00 00 2b 49 28 15 00 00 0a 72 90 01 04 6f 16 00 00 0a 7e 01 00 00 04 20 e8 03 00 00 73 17 00 00 0a 0c 07 08 07 6f 18 00 00 0a 1e 5b 6f 19 00 00 0a 6f 1a 00 00 0a 07 08 07 6f 1b 00 00 0a 1e 5b 6f 19 00 00 0a 6f 1c 00 00 0a 2b 07 6f 1d 00 00 0a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
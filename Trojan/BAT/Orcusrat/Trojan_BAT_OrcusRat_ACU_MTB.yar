
rule Trojan_BAT_OrcusRat_ACU_MTB{
	meta:
		description = "Trojan:BAT/OrcusRat.ACU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {13 09 2b 2d 11 09 6f 90 01 03 0a 13 0a 00 72 90 01 03 70 11 0a 2d 03 14 2b 07 11 0a 90 00 } //01 00 
		$a_01_1 = {31 00 39 00 33 00 2e 00 31 00 33 00 38 00 2e 00 31 00 39 00 35 00 2e 00 32 00 31 00 31 00 } //01 00  193.138.195.211
		$a_01_2 = {52 00 75 00 6e 00 6e 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //00 00  Runner.exe
	condition:
		any of ($a_*)
 
}

rule Trojan_BAT_Tiny_SPQX_MTB{
	meta:
		description = "Trojan:BAT/Tiny.SPQX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 03 00 "
		
	strings :
		$a_03_0 = {11 05 07 11 04 11 05 1b 58 09 11 05 59 20 84 13 00 00 32 07 20 00 10 00 00 2b 04 09 11 05 59 16 6f 90 01 03 0a 58 13 05 00 11 05 09 fe 04 13 08 11 08 2d cb 90 00 } //01 00 
		$a_81_1 = {43 73 68 61 72 70 44 65 6d 6f 2e 70 64 62 } //00 00  CsharpDemo.pdb
	condition:
		any of ($a_*)
 
}
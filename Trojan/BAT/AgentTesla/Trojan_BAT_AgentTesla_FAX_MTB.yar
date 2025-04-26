
rule Trojan_BAT_AgentTesla_FAX_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.FAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {0d 16 13 04 2b 23 00 08 11 04 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 13 06 09 11 06 6f ?? 00 00 0a 00 11 04 18 58 13 04 00 11 04 08 6f ?? 00 00 0a fe 04 13 07 11 07 2d cd } //3
		$a_01_1 = {51 00 75 00 61 00 6e 00 6c 00 79 00 62 00 61 00 6e 00 68 00 61 00 6e 00 67 00 46 00 41 00 48 00 41 00 53 00 41 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //2 QuanlybanhangFAHASA.Properties.Resources
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}
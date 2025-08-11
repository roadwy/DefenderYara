
rule Trojan_BAT_PureLogs_AB_MTB{
	meta:
		description = "Trojan:BAT/PureLogs.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {7e 72 00 00 04 20 17 40 9b c0 20 a5 ee 07 95 61 20 60 7d 1a 23 61 7d 78 00 00 04 20 40 00 00 00 38 8c ec ff ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
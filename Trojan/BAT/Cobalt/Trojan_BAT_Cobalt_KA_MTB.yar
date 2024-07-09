
rule Trojan_BAT_Cobalt_KA_MTB{
	meta:
		description = "Trojan:BAT/Cobalt.KA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 04 1f 40 2e 13 11 04 1f 5e 2e 39 2b 6c 06 09 1f 31 6f ?? 00 00 0a 2b 61 06 09 1f 32 } //10
		$a_01_1 = {4e 00 63 00 71 00 65 00 76 00 6b 00 59 00 45 00 55 00 74 00 4d 00 62 00 } //1 NcqevkYEUtMb
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}
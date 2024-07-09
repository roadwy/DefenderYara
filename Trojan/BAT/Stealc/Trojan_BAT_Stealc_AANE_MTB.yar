
rule Trojan_BAT_Stealc_AANE_MTB{
	meta:
		description = "Trojan:BAT/Stealc.AANE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 25 08 6f ?? 00 00 0a 25 17 6f ?? 00 00 0a 25 18 28 ?? 00 00 06 25 06 6f ?? 00 00 0a 28 ?? 00 00 06 07 16 07 8e 69 28 ?? 00 00 06 0d } //4
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}
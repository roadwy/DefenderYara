
rule Trojan_BAT_CryptInject_RN_MSR{
	meta:
		description = "Trojan:BAT/CryptInject.RN!MSR,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {02 04 8f 0d 00 00 01 25 47 03 04 28 90 01 01 00 00 06 61 d2 52 2a 90 00 } //1
		$a_02_1 = {02 03 06 28 90 01 01 00 00 06 06 17 58 0a 06 02 8e 69 32 ee 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}
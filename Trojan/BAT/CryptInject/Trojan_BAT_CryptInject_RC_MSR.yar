
rule Trojan_BAT_CryptInject_RC_MSR{
	meta:
		description = "Trojan:BAT/CryptInject.RC!MSR,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {07 09 16 11 05 6f ?? ?? ?? 0a 26 16 13 06 2b 11 09 11 06 09 11 06 91 04 61 d2 9c 11 06 17 58 13 06 11 06 09 8e 69 32 e8 28 ?? ?? ?? 0a 09 6f ?? ?? ?? 0a 2a } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
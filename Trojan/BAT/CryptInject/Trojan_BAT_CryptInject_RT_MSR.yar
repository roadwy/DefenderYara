
rule Trojan_BAT_CryptInject_RT_MSR{
	meta:
		description = "Trojan:BAT/CryptInject.RT!MSR,SIGNATURE_TYPE_PEHSTR,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 06 8f 03 00 00 01 25 47 03 06 03 8e 69 5d 91 61 d2 52 06 17 58 0a 06 02 8e 69 32 e3 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
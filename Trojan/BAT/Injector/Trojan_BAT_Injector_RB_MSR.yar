
rule Trojan_BAT_Injector_RB_MSR{
	meta:
		description = "Trojan:BAT/Injector.RB!MSR,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_02_0 = {02 1f 10 07 16 07 8e b7 28 ?? ?? ?? 0a 16 07 8e b7 17 da 0d 0c 2b 11 07 08 07 08 91 02 08 1f 10 5d 91 61 9c 08 17 d6 0c 08 09 31 eb 07 2a } //5
	condition:
		((#a_02_0  & 1)*5) >=5
 
}
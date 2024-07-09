
rule Trojan_BAT_Redcap_PSWI_MTB{
	meta:
		description = "Trojan:BAT/Redcap.PSWI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {a2 25 1e 72 45 14 00 70 a2 28 ?? 00 00 0a 6f ?? 00 00 0a 0a 7e 11 00 00 04 28 ?? 00 00 0a 74 16 00 00 01 0b 07 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
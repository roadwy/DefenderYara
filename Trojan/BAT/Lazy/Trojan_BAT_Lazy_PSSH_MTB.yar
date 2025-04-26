
rule Trojan_BAT_Lazy_PSSH_MTB{
	meta:
		description = "Trojan:BAT/Lazy.PSSH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {6f 18 00 00 0a 07 72 73 00 00 70 73 19 00 00 0a 08 6f ?? 00 00 0a 06 7b 05 00 00 04 6f ?? 00 00 0a 26 08 28 ?? 00 00 0a 2d 57 73 14 00 00 0a 0d } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}

rule Trojan_BAT_Nanocore_ZPAA_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.ZPAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 18 5b 1f 10 59 0d 06 09 03 08 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 25 26 07 09 07 8e 69 5d 91 61 d2 9c 08 18 58 0c 08 03 6f ?? 00 00 0a 32 b2 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
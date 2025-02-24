
rule Trojan_BAT_Dnoper_AMV_MTB{
	meta:
		description = "Trojan:BAT/Dnoper.AMV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 0d 09 6f ?? 00 00 0a 72 ?? 00 00 70 28 ?? 00 00 0a 39 ?? 00 00 00 09 14 14 6f ?? 00 00 0a 26 08 17 58 0c 08 07 8e 69 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
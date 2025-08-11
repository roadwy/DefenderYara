
rule Trojan_BAT_Stealer_MGH_MTB{
	meta:
		description = "Trojan:BAT/Stealer.MGH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 13 20 30 01 00 00 91 2b ef 03 19 8d 05 00 00 01 25 16 12 07 20 a4 00 00 00 20 8e 00 00 00 28 ?? 00 00 06 9c 25 17 12 07 20 76 02 00 00 20 5d 02 00 00 28 ?? 00 00 06 9c 25 18 12 07 20 de 03 00 00 20 f2 03 00 00 28 ?? 00 00 06 9c 6f 62 00 00 0a 18 13 12 38 8f fe ff ff 20 ee 00 00 00 20 da 00 00 00 28 ?? 00 00 06 13 0c 12 0c } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
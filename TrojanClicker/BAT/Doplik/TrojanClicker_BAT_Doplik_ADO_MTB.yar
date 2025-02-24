
rule TrojanClicker_BAT_Doplik_ADO_MTB{
	meta:
		description = "TrojanClicker:BAT/Doplik.ADO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 06 17 6f ?? 00 00 0a 00 73 0b 00 00 0a 0b 07 72 01 00 00 70 6f ?? 00 00 0a 00 07 72 13 00 00 70 6f ?? 00 00 0a 00 06 07 73 0d 00 00 0a 80 01 00 00 04 7e 01 00 00 04 6f } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
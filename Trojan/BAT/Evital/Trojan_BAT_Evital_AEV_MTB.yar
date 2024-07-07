
rule Trojan_BAT_Evital_AEV_MTB{
	meta:
		description = "Trojan:BAT/Evital.AEV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {13 14 11 06 11 14 19 6f 8d 00 00 0a 11 14 17 6f 8d 00 00 0a 72 cf 15 00 70 11 14 18 6f 8d 00 00 0a 28 07 00 00 0a 11 14 16 6f 8d 00 00 0a 11 09 6f 64 00 00 06 11 0b 6f 79 00 00 06 28 f4 00 00 06 6f 08 00 00 0a 12 0f 28 8e 00 00 0a 2d aa } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
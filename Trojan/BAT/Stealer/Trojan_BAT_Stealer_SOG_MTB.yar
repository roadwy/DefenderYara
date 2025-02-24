
rule Trojan_BAT_Stealer_SOG_MTB{
	meta:
		description = "Trojan:BAT/Stealer.SOG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {72 65 00 00 70 0c 72 ?? ?? ?? 70 0d 72 5a 01 00 70 13 04 09 72 9a 01 00 70 28 15 00 00 0a 6f 16 00 00 0a 6f 17 00 00 0a 0d 09 28 18 00 00 0a 74 13 00 00 01 13 05 72 b0 01 00 70 13 06 11 05 72 e8 01 00 70 6f 19 00 00 0a 00 72 f0 01 00 70 13 07 72 ?? ?? ?? 70 13 08 11 08 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
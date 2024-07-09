
rule Trojan_BAT_Androm_CST_MTB{
	meta:
		description = "Trojan:BAT/Androm.CST!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 07 6f 06 00 00 0a 07 03 6f ?? ?? ?? ?? 5d 0c 03 08 6f ?? ?? ?? ?? 0d 09 61 d1 13 04 06 11 04 6f ?? ?? ?? ?? 26 07 17 58 0b 07 02 6f ?? ?? ?? ?? 32 cd } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
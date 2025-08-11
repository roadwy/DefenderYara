
rule Trojan_BAT_Netwire_CH_MTB{
	meta:
		description = "Trojan:BAT/Netwire.CH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {6a 5f 6d 0b 11 04 06 95 13 06 11 04 06 11 04 07 95 9e 11 04 07 11 06 9e 09 11 07 02 11 07 91 11 04 11 04 06 95 11 04 07 95 58 6e 20 ?? ?? ?? ?? 6a 5f 69 95 61 d2 9c 00 11 07 17 58 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}

rule Trojan_BAT_Netwire_BAM_MTB{
	meta:
		description = "Trojan:BAT/Netwire.BAM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 07 02 8e b7 5d 02 07 02 8e b7 5d 91 08 07 08 8e b7 5d 91 61 02 07 17 58 02 8e b7 5d 91 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 9c 07 15 58 0b 07 16 2f cb } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
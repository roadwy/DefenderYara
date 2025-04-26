
rule Trojan_BAT_Jalapeno_AVGA_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.AVGA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 11 04 02 11 04 91 07 11 04 07 8e b7 5d 91 61 09 11 04 09 8e b7 5d 91 61 9c 7e ?? 00 00 04 1f 1c 94 fe ?? ?? 00 00 01 58 7e ?? 00 00 04 1f 1d 94 59 13 06 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
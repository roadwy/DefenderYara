
rule Trojan_BAT_Stealer_VGT_MTB{
	meta:
		description = "Trojan:BAT/Stealer.VGT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 72 47 00 00 70 28 0c 00 00 0a 0b 73 0d 00 00 0a 0c 73 0e 00 00 0a 0d 09 08 06 07 6f ?? 00 00 0a 17 73 10 00 00 0a 13 04 11 04 03 16 03 8e 69 6f ?? 00 00 0a 09 6f ?? 00 00 0a 13 05 dd 29 00 00 00 11 04 39 07 00 00 00 11 04 6f ?? 00 00 0a dc 09 39 06 00 00 00 09 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
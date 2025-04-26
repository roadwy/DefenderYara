
rule Trojan_BAT_Vidar_PSJO_MTB{
	meta:
		description = "Trojan:BAT/Vidar.PSJO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {08 11 0a 8f 09 00 00 02 11 0c 08 11 0a 8f 09 00 00 02 7b 2f 00 00 04 16 28 04 00 00 06 7d 34 00 00 04 17 73 7d 00 00 0a 08 11 0a 8f 09 00 00 02 7b 34 00 00 04 6f 34 00 00 0a 13 0d dd 14 fb ff ff } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
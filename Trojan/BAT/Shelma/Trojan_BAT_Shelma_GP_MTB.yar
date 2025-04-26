
rule Trojan_BAT_Shelma_GP_MTB{
	meta:
		description = "Trojan:BAT/Shelma.GP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {72 c8 19 00 70 0b 72 ca 19 00 70 28 0c 00 00 06 0c 72 ca 19 00 70 28 0c 00 00 06 0d 73 1b 00 00 0a 13 04 06 28 1c 00 00 0a 73 1d 00 00 0a 13 05 11 05 11 04 08 09 } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}
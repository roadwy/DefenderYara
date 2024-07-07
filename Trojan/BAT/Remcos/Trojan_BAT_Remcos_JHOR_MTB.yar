
rule Trojan_BAT_Remcos_JHOR_MTB{
	meta:
		description = "Trojan:BAT/Remcos.JHOR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 05 7e 1c 00 00 04 29 12 00 00 11 17 7e 1d 00 00 04 29 15 00 00 11 00 14 28 25 00 00 0a 00 11 05 7e 1e 00 00 04 29 16 00 00 11 26 72 a8 02 00 70 28 90 01 03 0a 00 11 05 7e 1f 00 00 04 29 01 00 00 11 00 72 01 00 00 70 72 c8 02 00 70 28 90 01 03 0a 28 90 01 03 0a fe 0e 0e 00 fe 0c 0e 00 2c 0a 72 f4 02 00 70 28 90 01 03 0a 00 00 28 90 01 03 0a 00 06 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
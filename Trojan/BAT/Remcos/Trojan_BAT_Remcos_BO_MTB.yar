
rule Trojan_BAT_Remcos_BO_MTB{
	meta:
		description = "Trojan:BAT/Remcos.BO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {03 19 fe 04 16 fe 01 0c 08 2c 0c 00 02 04 28 ?? 00 00 06 00 00 2b 13 03 16 fe 02 0d 09 } //4
		$a_01_1 = {03 16 fe 02 0d 09 2c 0b 00 02 03 04 28 } //1
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}

rule Trojan_BAT_Nanocore_CEZ_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.CEZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0d 09 1f 21 fe 04 16 fe 01 09 1f 7e fe 02 16 fe 01 5f 13 06 11 06 2c 20 11 04 1f 21 09 1f 0e d6 1f 5e 5d d6 28 90 01 03 0a 28 90 01 03 0a 28 90 01 03 0a 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
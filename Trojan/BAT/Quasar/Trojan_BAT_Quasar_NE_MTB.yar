
rule Trojan_BAT_Quasar_NE_MTB{
	meta:
		description = "Trojan:BAT/Quasar.NE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {d0 09 00 00 01 28 90 01 03 0a 20 90 01 03 06 28 90 01 03 06 28 90 01 03 0a 02 28 90 01 03 06 75 90 01 03 01 14 6f 90 01 03 0a 75 90 01 03 1b 28 90 01 03 2b 90 00 } //5
		$a_01_1 = {5a 74 67 66 65 78 75 73 } //1 Ztgfexus
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}
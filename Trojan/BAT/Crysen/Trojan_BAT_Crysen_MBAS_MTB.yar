
rule Trojan_BAT_Crysen_MBAS_MTB{
	meta:
		description = "Trojan:BAT/Crysen.MBAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 0c 08 28 90 01 01 00 00 0a 03 6f 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 2b 3f 08 6f 90 01 01 00 00 0a 2b 0c 28 90 01 01 00 00 0a 03 6f 90 01 01 00 00 0a 0a 73 90 01 01 00 00 0a 0d 09 06 2b 10 90 00 } //1
		$a_01_1 = {fe eb e8 eb de eb db eb d5 eb eb eb f6 eb fc eb c7 eb d8 eb d6 eb ed } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
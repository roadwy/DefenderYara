
rule Trojan_BAT_Remcos_MBIC_MTB{
	meta:
		description = "Trojan:BAT/Remcos.MBIC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {13 04 12 01 07 8e 69 11 04 8e 69 58 28 90 01 01 00 00 06 12 01 11 04 90 00 } //1
		$a_01_1 = {51 6e 6f 76 44 52 6b 67 66 6e 6f 4f 61 69 6b 4d 4d 73 71 4c 2e 72 65 73 } //1 QnovDRkgfnoOaikMMsqL.res
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
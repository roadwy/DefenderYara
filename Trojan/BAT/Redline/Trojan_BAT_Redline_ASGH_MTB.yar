
rule Trojan_BAT_Redline_ASGH_MTB{
	meta:
		description = "Trojan:BAT/Redline.ASGH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 06 06 6f ?? 00 00 0a 06 6f ?? 00 00 0a 6f ?? 00 00 0a 0b 02 73 ?? 00 00 0a 0c 08 07 16 73 ?? 00 00 0a 0d 09 73 ?? 00 00 0a 13 04 11 04 02 8e 69 6f ?? 00 00 0a 13 05 de 34 11 04 2c 07 11 04 6f ?? 00 00 0a dc 09 2c 06 09 6f ?? 00 00 0a dc } //4
		$a_81_1 = {30 45 37 4a 43 6d 66 4d 4f 64 67 52 52 53 44 70 44 64 74 30 45 } //1 0E7JCmfMOdgRRSDpDdt0E
	condition:
		((#a_03_0  & 1)*4+(#a_81_1  & 1)*1) >=5
 
}
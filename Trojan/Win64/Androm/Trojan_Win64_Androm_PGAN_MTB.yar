
rule Trojan_Win64_Androm_PGAN_MTB{
	meta:
		description = "Trojan:Win64/Androm.PGAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {99 41 f7 f8 48 8b 04 24 83 c2 1d 81 c2 78 03 00 00 31 d1 88 ca 48 63 4c 24 0c 88 14 08 8b 44 24 0c 83 c0 01 89 44 24 0c eb b7 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
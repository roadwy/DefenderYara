
rule Trojan_BAT_Fsysna_AFS_MTB{
	meta:
		description = "Trojan:BAT/Fsysna.AFS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {7e 13 00 00 0a 0a 73 14 00 00 0a 0b 07 72 1f 00 00 70 6f ?? 00 00 0a 0a de 0a 07 2c 06 07 6f } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_Fsysna_AFS_MTB_2{
	meta:
		description = "Trojan:BAT/Fsysna.AFS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {13 06 11 05 11 06 16 11 06 8e 69 6f 21 00 00 0a 13 07 2b 1e 00 08 11 06 16 11 07 6f 22 00 00 0a 00 11 05 11 06 16 11 06 8e 69 6f 21 00 00 0a 13 07 00 11 07 16 fe 02 13 09 11 09 2d d7 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_Fsysna_AFS_MTB_3{
	meta:
		description = "Trojan:BAT/Fsysna.AFS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {0b 2b 4d 12 01 28 ?? 00 00 0a 0c 08 73 21 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 0d 28 ?? 00 00 0a 09 28 } //2
		$a_01_1 = {74 00 77 00 6f 00 62 00 69 00 74 00 36 00 39 00 20 00 6f 00 72 00 20 00 6c 00 69 00 66 00 65 00 6f 00 66 00 61 00 63 00 6f 00 6f 00 6b 00 69 00 65 00 } //1 twobit69 or lifeofacookie
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}

rule Trojan_O97M_Malexutr_SA_MTB{
	meta:
		description = "Trojan:O97M/Malexutr.SA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_02_0 = {20 3d 20 22 70 22 20 2b 20 90 02 08 6f 90 02 08 77 90 02 08 45 90 02 08 72 90 02 08 73 90 02 08 68 90 02 08 65 90 02 08 6c 90 02 08 6c 90 00 } //5
		$a_00_1 = {20 3d 20 53 74 72 52 65 76 65 72 73 65 28 } //1  = StrReverse(
	condition:
		((#a_02_0  & 1)*5+(#a_00_1  & 1)*1) >=6
 
}
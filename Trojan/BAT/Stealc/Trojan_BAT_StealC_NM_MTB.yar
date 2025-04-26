
rule Trojan_BAT_StealC_NM_MTB{
	meta:
		description = "Trojan:BAT/StealC.NM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 05 11 02 6f ?? 00 00 0a 20 ?? 00 00 00 28 ?? 00 00 06 39 ?? ff ff ff 26 38 } //5
		$a_01_1 = {69 6e 64 75 73 74 72 69 61 6c 63 75 73 74 6f 6d 74 6f 75 72 } //1 industrialcustomtour
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}
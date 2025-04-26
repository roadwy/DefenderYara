
rule Trojan_AndroidOS_SAgnt_V_MTB{
	meta:
		description = "Trojan:AndroidOS/SAgnt.V!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_00_0 = {48 03 07 02 d5 33 ff 00 da 04 02 02 62 05 49 0b e2 06 03 04 49 06 05 06 50 06 01 04 d8 04 04 01 dd 03 03 0f 49 03 05 03 50 03 01 04 d8 02 02 01 28 e5 } //1
	condition:
		((#a_00_0  & 1)*1) >=1
 
}
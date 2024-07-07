
rule Trojan_AndroidOS_Meds_A_MTB{
	meta:
		description = "Trojan:AndroidOS/Meds.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_00_0 = {49 02 00 01 13 03 7a 00 36 32 f9 ff 49 02 00 01 13 03 61 00 34 32 f3 ff 49 02 00 01 d8 02 02 9f 8e 22 50 02 00 01 49 02 00 01 d8 02 02 1a d8 02 02 f6 dc 02 02 1a 8e 22 50 02 00 01 49 02 00 01 d8 02 02 61 8e 22 50 02 00 01 } //1
	condition:
		((#a_00_0  & 1)*1) >=1
 
}

rule Trojan_AndroidOS_Hiddap_A_MTB{
	meta:
		description = "Trojan:AndroidOS/Hiddap.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {1a 00 00 00 6e 10 90 01 02 04 00 0c 00 6e 10 90 01 02 04 00 0c 01 12 02 70 52 90 01 02 43 10 90 01 02 6e 10 90 01 02 04 00 0c 00 6e 10 90 01 02 04 00 0c 01 12 12 70 52 90 01 02 43 10 0e 00 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
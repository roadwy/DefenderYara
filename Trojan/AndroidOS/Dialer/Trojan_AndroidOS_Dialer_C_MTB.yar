
rule Trojan_AndroidOS_Dialer_C_MTB{
	meta:
		description = "Trojan:AndroidOS/Dialer.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {54 20 07 00 1a 01 72 00 6e 20 90 01 02 10 00 54 20 07 00 1a 01 bc 00 71 10 90 01 02 01 00 0c 01 6e 20 90 01 02 10 00 54 20 07 00 6e 20 90 01 02 02 00 90 00 } //01 00 
		$a_00_1 = {63 6f 6d 2f 6d 79 2f 6e 65 77 70 72 6f 6a 65 63 74 32 } //00 00  com/my/newproject2
	condition:
		any of ($a_*)
 
}
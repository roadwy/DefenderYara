
rule Trojan_AndroidOS_Dialer_C_MTB{
	meta:
		description = "Trojan:AndroidOS/Dialer.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {54 20 07 00 1a 01 72 00 6e 20 ?? ?? 10 00 54 20 07 00 1a 01 bc 00 71 10 ?? ?? 01 00 0c 01 6e 20 ?? ?? 10 00 54 20 07 00 6e 20 ?? ?? 02 00 } //1
		$a_00_1 = {63 6f 6d 2f 6d 79 2f 6e 65 77 70 72 6f 6a 65 63 74 32 } //1 com/my/newproject2
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}
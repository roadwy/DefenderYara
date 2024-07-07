
rule Trojan_BAT_Nanocore_NN_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.NN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 04 11 06 04 11 07 25 17 58 13 07 91 61 20 90 01 01 00 00 00 5f e0 95 11 06 1e 64 61 13 06 11 08 17 59 25 13 08 16 2f d9 90 00 } //5
		$a_01_1 = {66 73 64 67 73 72 78 64 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 fsdgsrxd.Resources.resources
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}
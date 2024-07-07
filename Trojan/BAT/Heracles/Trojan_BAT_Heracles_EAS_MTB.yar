
rule Trojan_BAT_Heracles_EAS_MTB{
	meta:
		description = "Trojan:BAT/Heracles.EAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {06 13 00 38 00 00 00 00 28 90 01 01 00 00 0a 11 00 6f 90 01 01 00 00 0a 28 90 01 01 00 00 0a 28 90 01 01 00 00 06 13 01 38 00 00 00 00 dd 90 01 01 00 00 00 26 38 00 00 00 00 dd 90 00 } //3
		$a_01_1 = {43 61 73 74 6c 65 2e 44 79 6e 61 6d 69 63 50 72 6f 78 79 2e 44 79 6e 50 72 6f 78 79 } //2 Castle.DynamicProxy.DynProxy
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}
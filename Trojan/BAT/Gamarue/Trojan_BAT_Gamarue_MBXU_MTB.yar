
rule Trojan_BAT_Gamarue_MBXU_MTB{
	meta:
		description = "Trojan:BAT/Gamarue.MBXU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {07 17 28 0a 00 00 06 07 1b 28 0a 00 00 06 61 8d 39 00 00 01 0c 07 08 16 08 8e } //3
		$a_01_1 = {73 65 74 5f 54 72 61 6e 73 70 6f 72 74 2e 72 65 73 6f 75 72 63 65 73 } //2 set_Transport.resources
		$a_01_2 = {5a 65 6e 4d 61 70 2e 65 78 65 00 6d 73 63 6f } //1
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=6
 
}
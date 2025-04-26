
rule Trojan_BAT_Remcos_AMU_MTB{
	meta:
		description = "Trojan:BAT/Remcos.AMU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {06 17 58 20 ff 00 00 00 5f 0a 07 05 06 95 58 20 ff 00 00 00 5f 0b 02 05 06 } //4
		$a_01_1 = {58 20 00 01 00 00 5e 26 04 08 03 08 91 05 09 95 61 d2 9c 08 17 58 0c } //1
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}
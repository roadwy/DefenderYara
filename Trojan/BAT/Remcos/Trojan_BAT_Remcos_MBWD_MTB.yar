
rule Trojan_BAT_Remcos_MBWD_MTB{
	meta:
		description = "Trojan:BAT/Remcos.MBWD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {06 07 1f 2a 5a 58 0a 00 07 17 58 0b 07 1b fe 04 0c 08 2d eb } //2
		$a_01_1 = {53 00 79 00 73 00 74 00 65 00 6d 00 2e 00 52 00 65 00 66 00 6c 00 65 00 63 00 74 00 69 00 6f 00 6e } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}
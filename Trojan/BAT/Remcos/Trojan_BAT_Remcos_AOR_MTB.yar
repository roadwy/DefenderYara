
rule Trojan_BAT_Remcos_AOR_MTB{
	meta:
		description = "Trojan:BAT/Remcos.AOR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 0a 02 73 13 00 00 0a 0b 07 06 16 73 14 00 00 0a 0c 00 02 8e 69 8d 1e 00 00 01 0d 08 09 16 09 8e 69 6f ?? ?? ?? 0a 13 04 09 11 04 } //2
		$a_01_1 = {43 00 68 00 65 00 63 00 6b 00 20 00 43 00 61 00 72 00 20 00 46 00 6f 00 72 00 6d 00 } //1 Check Car Form
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}
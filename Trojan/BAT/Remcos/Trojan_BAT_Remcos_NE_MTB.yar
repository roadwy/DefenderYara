
rule Trojan_BAT_Remcos_NE_MTB{
	meta:
		description = "Trojan:BAT/Remcos.NE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {08 07 02 11 04 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 58 0c 11 04 18 58 13 04 11 04 1f 0f 32 e3 } //1
		$a_01_1 = {51 00 72 00 65 00 6f 00 6b 00 6e 00 72 00 65 00 72 00 78 00 70 00 62 00 69 00 67 00 6f 00 68 00 69 00 68 00 61 00 73 00 63 00 64 00 } //1 Qreoknrerxpbigohihascd
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
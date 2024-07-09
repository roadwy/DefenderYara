
rule Trojan_BAT_Remcos_AEKW_MTB{
	meta:
		description = "Trojan:BAT/Remcos.AEKW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 07 02 8e 69 5d 02 07 02 8e 69 5d 91 06 07 1f 16 5d 91 61 28 ?? ?? ?? 06 02 07 17 58 02 8e 69 5d 91 } //2
		$a_01_1 = {4c 00 61 00 6e 00 64 00 72 00 79 00 } //1 Landry
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}
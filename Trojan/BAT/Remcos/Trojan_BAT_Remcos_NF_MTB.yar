
rule Trojan_BAT_Remcos_NF_MTB{
	meta:
		description = "Trojan:BAT/Remcos.NF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {5e 26 04 08 03 08 91 05 09 95 61 d2 9c 08 17 58 0c 08 03 8e 69 } //1
		$a_81_1 = {63 61 65 31 39 66 34 32 2d 33 36 36 62 2d 34 66 61 64 2d 62 38 34 32 2d 31 64 36 38 39 38 62 30 37 33 31 61 } //2 cae19f42-366b-4fad-b842-1d6898b0731a
	condition:
		((#a_01_0  & 1)*1+(#a_81_1  & 1)*2) >=3
 
}
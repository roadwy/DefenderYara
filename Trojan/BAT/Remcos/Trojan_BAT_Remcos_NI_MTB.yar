
rule Trojan_BAT_Remcos_NI_MTB{
	meta:
		description = "Trojan:BAT/Remcos.NI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 08 17 59 13 08 02 7b 33 01 00 04 11 04 7b 02 00 00 04 11 09 9e 14 13 04 2b 21 11 06 11 04 } //1
		$a_81_1 = {66 62 30 37 38 64 62 64 2d 62 39 38 38 2d 34 30 62 39 2d 62 38 62 30 2d 39 32 37 32 63 37 33 66 36 65 65 33 } //2 fb078dbd-b988-40b9-b8b0-9272c73f6ee3
	condition:
		((#a_01_0  & 1)*1+(#a_81_1  & 1)*2) >=3
 
}
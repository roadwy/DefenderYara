
rule Trojan_BAT_Jalapeno_PE_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.PE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_03_0 = {11 0c 11 09 6f ?? 00 00 0a 17 73 0d 00 00 0a 13 02 38 00 00 00 00 00 11 02 02 16 02 8e 69 6f ?? 00 00 0a 38 } //2
		$a_01_1 = {35 34 61 31 38 34 61 31 2d 64 34 64 62 2d 34 34 66 30 2d 39 66 32 38 2d 65 38 37 61 39 30 66 62 33 37 31 34 } //2 54a184a1-d4db-44f0-9f28-e87a90fb3714
		$a_01_2 = {46 6a 78 72 63 6f 74 77 70 69 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //2 Fjxrcotwpi.Properties.Resources.resources
		$a_01_3 = {73 14 00 00 0a 13 06 20 01 00 00 00 7e 16 00 00 04 7b 18 00 00 04 39 88 ff ff ff 26 20 07 00 00 00 38 7d ff ff ff 00 11 0a 8d 08 00 00 01 13 0b } //1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1) >=7
 
}
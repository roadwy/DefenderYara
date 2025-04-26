
rule Trojan_BAT_Heracles_KAV_MTB{
	meta:
		description = "Trojan:BAT/Heracles.KAV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {61 32 62 33 63 34 64 35 2d 65 36 66 37 2d 38 39 30 31 2d 61 62 63 64 2d 33 34 35 36 37 65 66 38 39 30 31 32 } //a2b3c4d5-e6f7-8901-abcd-34567ef89012  1
		$a_80_1 = {43 6f 73 6d 6f 53 70 68 65 72 65 20 49 6e 6e 6f 76 61 74 69 6f 6e 73 } //CosmoSphere Innovations  1
		$a_80_2 = {48 61 72 6e 65 73 73 69 6e 67 20 74 68 65 20 70 6f 77 65 72 20 6f 66 20 74 65 63 68 6e 6f 6c 6f 67 79 20 74 6f 20 64 72 69 76 65 20 67 6c 6f 62 61 6c 20 69 6e 6e 6f 76 61 74 69 6f 6e } //Harnessing the power of technology to drive global innovation  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}
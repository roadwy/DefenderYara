
rule Trojan_BAT_LummaStealer_KAK_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.KAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {62 33 64 34 63 35 65 36 2d 66 37 61 38 2d 39 30 31 32 2d 62 63 64 65 2d 33 34 35 36 37 65 66 38 39 30 31 32 } //b3d4c5e6-f7a8-9012-bcde-34567ef89012  1
		$a_80_1 = {4c 75 6d 69 6e 61 72 61 54 65 63 68 20 49 6e 6e 6f 76 61 74 69 6f 6e 73 } //LuminaraTech Innovations  1
		$a_80_2 = {69 6e 6e 6f 76 61 74 69 6f 6e 73 20 66 6f 72 20 61 20 62 72 69 67 68 74 65 72 20 74 65 63 68 6e 6f 6c 6f 67 69 63 61 6c 20 66 75 74 75 72 65 } //innovations for a brighter technological future  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}
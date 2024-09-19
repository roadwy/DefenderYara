
rule Trojan_BAT_LummaStealer_KAL_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.KAL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {64 33 65 34 66 35 61 36 2d 62 37 63 38 2d 39 30 31 32 2d 61 62 63 64 2d 32 33 34 35 36 65 66 37 38 39 30 31 } //d3e4f5a6-b7c8-9012-abcd-23456ef78901  1
		$a_80_1 = {48 79 70 65 72 69 6f 6e 54 65 63 68 20 49 6e 6e 6f 76 61 74 69 6f 6e 73 20 54 72 61 64 65 6d 61 72 6b } //HyperionTech Innovations Trademark  1
		$a_80_2 = {54 72 61 6e 73 66 6f 72 6d 69 6e 67 20 74 68 65 20 77 6f 72 6c 64 20 77 69 74 68 20 63 75 74 74 69 6e 67 2d 65 64 67 65 20 74 65 63 68 6e 6f 6c 6f 67 79 20 69 6e 6e 6f 76 61 74 69 6f 6e 73 } //Transforming the world with cutting-edge technology innovations  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}